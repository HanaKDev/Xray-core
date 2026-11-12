package command

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func exactHost(name string, ip ...[]byte) *dns.Config_HostMapping {
	return &dns.Config_HostMapping{Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: name}}}, Ip: ip}
}
func compareView(t *testing.T, p proto.Message) any {
	t.Helper()
	v, e := cathodeExpand(p)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestCathodeExactDNSHostsOrderAndMutation(t *testing.T) {
	a := &dns.Config{StaticHosts: []*dns.Config_HostMapping{exactHost("z.example", []byte{1, 1, 1, 1}, []byte{8, 8, 8, 8}), exactHost("a.example", []byte{9, 9, 9, 9})}}
	b := proto.Clone(a).(*dns.Config)
	b.StaticHosts[0], b.StaticHosts[1] = b.StaticHosts[1], b.StaticHosts[0]
	beforeA, beforeB := proto.Clone(a), proto.Clone(b)
	if !reflect.DeepEqual(compareView(t, a), compareView(t, b)) {
		t.Fatal("exact hosts permutation falsely differs")
	}
	if !proto.Equal(a, beforeA) || !proto.Equal(b, beforeB) {
		t.Fatal("comparison mutated input config")
	}
	// A real response change, within-host answer order and proxied domain changes
	// must not be hidden by sorting the disjoint exact-name host mappings.
	changed := proto.Clone(a).(*dns.Config)
	changed.StaticHosts[0].Ip[0][0] = 2
	if reflect.DeepEqual(compareView(t, a), compareView(t, changed)) {
		t.Fatal("changed IP masked")
	}
	changed = proto.Clone(a).(*dns.Config)
	changed.StaticHosts[0].Ip[0], changed.StaticHosts[0].Ip[1] = changed.StaticHosts[0].Ip[1], changed.StaticHosts[0].Ip[0]
	if reflect.DeepEqual(compareView(t, a), compareView(t, changed)) {
		t.Fatal("answer order masked")
	}
	changed = proto.Clone(a).(*dns.Config)
	changed.StaticHosts[0].ProxiedDomain = "alias.example"
	if reflect.DeepEqual(compareView(t, a), compareView(t, changed)) {
		t.Fatal("alias change masked")
	}
}
func TestCathodeDNSMatcherAndDuplicateOrderRemainSignificant(t *testing.T) {
	for _, kind := range []geodata.Domain_Type{geodata.Domain_Regex, geodata.Domain_Domain, geodata.Domain_Substr} {
		a := &dns.Config{StaticHosts: []*dns.Config_HostMapping{exactHost("example", []byte{1, 1, 1, 1}), exactHost("other", []byte{2, 2, 2, 2})}}
		a.StaticHosts[0].Domain.GetCustom().Type = kind
		b := proto.Clone(a).(*dns.Config)
		b.StaticHosts[0], b.StaticHosts[1] = b.StaticHosts[1], b.StaticHosts[0]
		if cathodeDNSHostOrder(a) != nil || reflect.DeepEqual(compareView(t, a), compareView(t, b)) {
			t.Fatal("possibly overlapping host rules reordered")
		}
	}
	for _, name := range []string{"a.example", "A.EXAMPLE", "a.example."} {
		a := &dns.Config{StaticHosts: []*dns.Config_HostMapping{exactHost("a.example", []byte{1, 1, 1, 1}), exactHost(name, []byte{2, 2, 2, 2})}}
		b := proto.Clone(a).(*dns.Config)
		b.StaticHosts[0], b.StaticHosts[1] = b.StaticHosts[1], b.StaticHosts[0]
		if cathodeDNSHostOrder(a) != nil || reflect.DeepEqual(compareView(t, a), compareView(t, b)) {
			t.Fatal("duplicate exact-name precedence hidden")
		}
	}
	a := &router.Config{Rule: []*router.RoutingRule{{RuleTag: "first"}, {RuleTag: "second"}}}
	b := proto.Clone(a).(*router.Config)
	b.Rule[0], b.Rule[1] = b.Rule[1], b.Rule[0]
	if reflect.DeepEqual(compareView(t, a), compareView(t, b)) {
		t.Fatal("routing order masked")
	}
}

func TestCathodeDNSUnknownHostFieldsRemainOrdered(t *testing.T) {
	a := &dns.Config{StaticHosts: []*dns.Config_HostMapping{exactHost("a.example", []byte{1, 1, 1, 1}), exactHost("z.example", []byte{2, 2, 2, 2})}}
	a.StaticHosts[0].ProtoReflect().SetUnknown([]byte{0x28, 1})
	if cathodeDNSHostOrder(a) != nil {
		t.Fatal("unknown future host semantics normalized")
	}
}
