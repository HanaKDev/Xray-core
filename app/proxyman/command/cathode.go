package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/metrics"
	r "github.com/xtls/xray-core/app/router"
	st "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	fr "github.com/xtls/xray-core/features/routing"
	fs "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
)

type cathodeRequest struct {
	Op       string   `json:"op"`
	Boot     string   `json:"boot"`
	Revision string   `json:"revision"`
	Config   []byte   `json:"config_pb"`
	Unlock   []string `json:"unlock"`
	Lock     []string `json:"lock"`
}
type cathodeSnapshot struct {
	Executable string          `json:"executable_sha256"`
	UserStats  bool            `json:"user_stats"`
	Boot       string          `json:"boot"`
	Revision   string          `json:"revision"`
	Build      string          `json:"build"`
	Config     []byte          `json:"config_pb"`
	Locks      map[string]bool `json:"locks"`
	Coverage   []string        `json:"coverage"`
}

func (s *handlerServer) cathode(ctx context.Context, raw *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	var q cathodeRequest
	if e := json.Unmarshal(raw.Value, &q); e != nil {
		return nil, e
	}
	s.s.CathodeMu.Lock()
	defer s.s.CathodeMu.Unlock()
	if q.Op == "usage" {
		m, ok := s.s.GetFeature(fs.ManagerType()).(*st.Manager)
		if !ok {
			return nil, fmt.Errorf("stats manager unavailable")
		}
		v, e := m.Usage()
		if e != nil {
			return nil, e
		}
		b, e := json.Marshal(v)
		return wrapperspb.Bytes(b), e
	}
	router, ok := s.s.GetFeature(fr.RouterType()).(*r.Router)
	if !ok {
		return nil, fmt.Errorf("router not supported")
	}
	rc, rev, locks := router.CathodeSnapshot()
	revision := fmt.Sprintf("%d:%d", s.s.CathodeRevision, rev)
	if q.Op == "route_apply" {
		if q.Boot != s.s.CathodeBoot || q.Revision != revision {
			return nil, fmt.Errorf("stale runtime version")
		}
		var input core.Config
		if e := proto.Unmarshal(q.Config, &input); e != nil {
			return nil, e
		}
		var candidate *r.Config
		for _, app := range input.App {
			if app.Type == "xray.app.router.Config" {
				v, e := app.GetInstance()
				if e != nil {
					return nil, e
				}
				candidate = v.(*r.Config)
			}
		}
		if candidate == nil {
			return nil, fmt.Errorf("missing compiled routing config")
		}
		if candidate.Script != "" {
			return nil, fmt.Errorf("script mode unsupported for managed routes")
		}
		for _, rule := range candidate.Rule {
			if tag := rule.GetTag(); tag != "" && s.ohm.GetHandler(tag) == nil {
				return nil, fmt.Errorf("outbound %s does not exist", tag)
			}
		}
		if e := router.CathodeReplace(candidate, rev, q.Unlock, q.Lock); e != nil {
			return nil, e
		}
		rc, rev, locks = router.CathodeSnapshot()
		revision = fmt.Sprintf("%d:%d", s.s.CathodeRevision, rev)
	} else if q.Op != "snapshot" && q.Op != "compare" {
		return nil, fmt.Errorf("unknown management operation")
	}
	if rc.Script != "" {
		return nil, fmt.Errorf("script runtime snapshot unsupported")
	}
	cfg := s.s.CathodeBootstrap()
	// Preserve meaningful configured order, including first/default outbound.
	cfg.Inbound = nil
	ih := s.ihm.ListHandlers(ctx)
	sort.Slice(ih, func(i, j int) bool { return ih[i].Tag() < ih[j].Tag() })
	for _, h := range ih {
		p := h.ProxySettings()
		if p == nil {
			continue
		}
		v, e := p.GetInstance()
		if e != nil {
			return nil, e
		}
		msg := v.(proto.Message)
		if pi, e := getInbound(h); e == nil {
			if um, ok := pi.(proxy.UserManager); ok {
				field := msg.ProtoReflect().Descriptor().Fields().ByName("users")
				if field == nil {
					return nil, fmt.Errorf("users projection unsupported")
				}
				users := um.GetUsers(ctx)
				sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
				msg.ProtoReflect().Clear(field)
				list := msg.ProtoReflect().Mutable(field).List()
				for _, u := range users {
					list.Append(protoreflect.ValueOfMessage(protocol.ToProtoUser(u).ProtoReflect()))
				}
			}
		}
		cfg.Inbound = append(cfg.Inbound, &core.InboundHandlerConfig{Tag: h.Tag(), ReceiverSettings: h.ReceiverSettings(), ProxySettings: serial.ToTypedMessage(msg)})
	}
	oldOut := cfg.Outbound
	cfg.Outbound = nil
	seenOut := map[string]bool{}
	appendOut := func(tag string) {
		h := s.ohm.GetHandler(tag)
		if h == nil {
			return
		}
		switch h.(type) {
		case *commander.Outbound, *metrics.Outbound:
			return
		}
		cfg.Outbound = append(cfg.Outbound, &core.OutboundHandlerConfig{Tag: h.Tag(), SenderSettings: h.SenderSettings(), ProxySettings: h.ProxySettings()})
		seenOut[tag] = true
	}
	if h := s.ohm.GetDefaultHandler(); h != nil {
		appendOut(h.Tag())
	}
	for _, h := range oldOut {
		if !seenOut[h.Tag] {
			appendOut(h.Tag)
		}
	}
	extra := []string{}
	for _, h := range s.ohm.ListHandlers(ctx) {
		if !seenOut[h.Tag()] {
			extra = append(extra, h.Tag())
		}
	}
	sort.Strings(extra)
	for _, tag := range extra {
		appendOut(tag)
	}
	for i, app := range cfg.App {
		if app.Type == "xray.app.router.Config" {
			cfg.App[i] = serial.ToTypedMessage(rc)
		}
	}
	if q.Op == "compare" {
		var expected core.Config
		if e := proto.Unmarshal(q.Config, &expected); e != nil {
			return nil, e
		}
		normalize := func(c *core.Config) error {
			sort.Slice(c.Inbound, func(i, j int) bool { return c.Inbound[i].Tag < c.Inbound[j].Tag })
			for _, h := range c.Inbound {
				v, e := h.ProxySettings.GetInstance()
				if e != nil {
					return e
				}
				m := v.(proto.Message).ProtoReflect()
				f := m.Descriptor().Fields().ByName("users")
				if f == nil {
					continue
				}
				l := m.Get(f).List()
				us := []*protocol.User{}
				for i := 0; i < l.Len(); i++ {
					u := l.Get(i).Message().Interface().(*protocol.User)
					mu, e := u.ToMemoryUser()
					if e != nil {
						return e
					}
					us = append(us, protocol.ToProtoUser(mu))
				}
				sort.Slice(us, func(i, j int) bool { return us[i].Email < us[j].Email })
				m.Clear(f)
				for _, u := range us {
					m.Mutable(f).List().Append(protoreflect.ValueOfMessage(u.ProtoReflect()))
				}
				h.ProxySettings = serial.ToTypedMessage(v.(proto.Message))
			}
			return nil
		}
		if e := normalize(&expected); e != nil {
			return nil, e
		}
		if e := normalize(cfg); e != nil {
			return nil, e
		}

		ev, e := cathodeExpand(&expected)
		if e != nil {
			return nil, e
		}
		av, e := cathodeExpand(cfg)
		if e != nil {
			return nil, e
		}
		diff := []string{}
		var walk func(any, any, string)
		walk = func(a, b any, path string) {
			if reflect.DeepEqual(a, b) {
				return
			}
			am, aok := a.(map[string]any)
			bm, bok := b.(map[string]any)
			if aok && bok {
				keys := map[string]bool{}
				for k := range am {
					keys[k] = true
				}
				for k := range bm {
					keys[k] = true
				}
				for k := range keys {
					walk(am[k], bm[k], path+"."+k)
				}
				return
			}
			aa, aok := a.([]any)
			ba, bok := b.([]any)
			if aok && bok && len(aa) == len(ba) {
				for i := range aa {
					walk(aa[i], ba[i], fmt.Sprintf("%s[%d]", path, i))
				}
				return
			}
			diff = append(diff, path)
		}
		walk(ev, av, "config")
		sort.Strings(diff)
		state := "partial-match"
		if len(diff) > 0 {
			state = "drift"
		}
		raw, e := json.Marshal(map[string]any{"boot": s.s.CathodeBoot, "revision": revision, "equal": len(diff) == 0, "state": state, "differences": diff, "unverified": []string{"loaded-resource-content", "transient-balancer-state", "hot-certificate-content"}, "coverage": "configured fields, active users and routing; resources not fingerprinted"})
		return wrapperspb.Bytes(raw), e
	}
	b, e := proto.Marshal(cfg)
	if e != nil {
		return nil, e
	}
	p := s.s.GetFeature(policy.ManagerType()).(policy.Manager).ForLevel(0)
	out, e := json.Marshal(cathodeSnapshot{Executable: cathodeBinaryHash(), UserStats: p.Stats.UserUplink && p.Stats.UserDownlink, Boot: s.s.CathodeBoot, Revision: revision, Build: strings.Join(core.VersionStatement(), " "), Config: b, Locks: locks, Coverage: []string{"bootstrap-static", "active-users", "active-routing"}})
	return wrapperspb.Bytes(out), e
}

type cathodeAPI interface {
	cathode(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
}

func registerCathode(g *grpc.Server, s *handlerServer) {
	g.RegisterService(&grpc.ServiceDesc{ServiceName: "cathode.core.v1.Management", HandlerType: (*cathodeAPI)(nil), Methods: []grpc.MethodDesc{{MethodName: "Call", Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, inter grpc.UnaryServerInterceptor) (interface{}, error) {
		in := new(wrapperspb.BytesValue)
		if e := dec(in); e != nil {
			return nil, e
		}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.(cathodeAPI).cathode(ctx, req.(*wrapperspb.BytesValue))
		}
		if inter != nil {
			return inter(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/cathode.core.v1.Management/Call"}, handler)
		}
		return handler(ctx, in)
	}}}}, s)
}

func cathodeExpand(p proto.Message) (any, error) {
	m := p.ProtoReflect()
	if m.Descriptor().FullName() == "xray.common.serial.TypedMessage" {
		t := p.(*serial.TypedMessage)
		v, e := t.GetInstance()
		if e != nil {
			return nil, e
		}
		value, e := cathodeExpand(v.(proto.Message))
		return map[string]any{"type": t.Type, "value": value}, e
	}
	out := map[string]any{}
	var err error
	var value func(protoreflect.FieldDescriptor, protoreflect.Value) (any, error)
	value = func(f protoreflect.FieldDescriptor, v protoreflect.Value) (any, error) {
		switch f.Kind() {
		case protoreflect.MessageKind:
			return cathodeExpand(v.Message().Interface())
		case protoreflect.BytesKind:
			return hex.EncodeToString(v.Bytes()), nil
		default:
			return v.Interface(), nil
		}
	}
	m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		var x any
		if f.IsList() {
			a := []any{}
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				z, e := value(f, l.Get(i))
				if e != nil {
					err = e
					return false
				}
				a = append(a, z)
			}
			x = a
		} else if f.IsMap() {
			a := map[string]any{}
			v.Map().Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
				z, e := value(f.MapValue(), mv)
				if e != nil {
					err = e
					return false
				}
				a[fmt.Sprint(k.Interface())] = z
				return true
			})
			x = a
		} else {
			x, err = value(f, v)
		}
		out[string(f.Name())] = x
		return err == nil
	})
	if u := m.GetUnknown(); len(u) > 0 {
		out["unknown"] = hex.EncodeToString(u)
	}
	return out, err
}

var binaryOnce sync.Once
var binaryDigest string

func cathodeBinaryHash() string {
	binaryOnce.Do(func() {
		path := "/proc/self/exe"
		f, e := os.Open(path)
		if e != nil {
			path, e = os.Executable()
			if e != nil {
				return
			}
			f, e = os.Open(path)
			if e != nil {
				return
			}
		}
		defer f.Close()
		h := sha256.New()
		if _, e = io.Copy(h, f); e == nil {
			binaryDigest = fmt.Sprintf("%x", h.Sum(nil))
		}
	})
	return binaryDigest
}
