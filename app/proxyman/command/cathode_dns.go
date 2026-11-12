package command

import (
	"sort"
	"strings"

	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

// cathodeDNSHostOrder canonicalizes only disjoint exact-name entries for the
// semantic comparison view. JSON hosts is an object, so its map iteration order
// is not stable across compiler processes. IP response order is significant and
// must be retained. Mixed matchers, duplicate names and unknown rule shapes stay
// ordered, since their overlap/precedence cannot be proven irrelevant here.
// Neither the runtime config nor the exported raw PB is mutated.
func cathodeDNSHostOrder(p proto.Message) []int {
	c, ok := p.(*dns.Config)
	if !ok || len(c.StaticHosts) < 2 {
		return nil
	}
	keys := make([]string, len(c.StaticHosts))
	order := make([]int, len(c.StaticHosts))
	seen := map[string]bool{}
	for i, h := range c.StaticHosts {
		if h == nil || h.Domain == nil || len(h.ProtoReflect().GetUnknown()) != 0 || len(h.Domain.ProtoReflect().GetUnknown()) != 0 {
			return nil
		}
		d := h.Domain.GetCustom()
		if d == nil || d.Type != geodata.Domain_Full || len(d.ProtoReflect().GetUnknown()) != 0 || len(d.Attribute) != 0 || d.Value == "" {
			return nil
		}
		// Be conservative about case and trailing-dot aliases: do not normalize if
		// two entries might address the same name, even if their raw spelling differs.
		key := strings.TrimRight(strings.ToLower(d.Value), ".")
		if key == "" || seen[key] {
			return nil
		}
		seen[key] = true
		keys[i] = key
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return keys[order[i]] < keys[order[j]] })
	return order
}
