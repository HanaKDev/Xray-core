package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/reality"
	"google.golang.org/protobuf/proto"
)

func TestREALITYPerInboundKeyShareCompatibility(t *testing.T) {
	// Synthetic key; never use production secrets in repository tests.
	base := `{"target":"127.0.0.1:443","serverNames":["example.com"],"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortIds":[""]`
	for _, tc := range []struct {
		name, extra string
		want        bool
	}{
		{"default", "", false},
		{"enabled", `,"ignoreClientHelloKeyShearMismatch":true`, true},
		{"explicit-false", `,"ignoreClientHelloKeyShearMismatch":false`, false},
		{"default-after-enabled", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c conf.REALITYConfig
			if err := json.Unmarshal([]byte(base+tc.extra+"}"), &c); err != nil {
				t.Fatal(err)
			}
			msg, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			data, err := proto.Marshal(msg)
			if err != nil {
				t.Fatal(err)
			}
			var decoded reality.Config
			if err := proto.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			native := decoded.GetREALITYConfig()
			if native.IgnoreClientHelloKeyShearMismatch != tc.want {
				t.Fatal("flag lost or leaked between inbound configurations")
			}
			if native.Clone().IgnoreClientHelloKeyShearMismatch != tc.want {
				t.Fatal("flag lost in native Clone")
			}
		})
	}
}

func TestREALITYRejectClientKeyShareCompatibility(t *testing.T) {
	c := conf.REALITYConfig{IgnoreClientHelloKeyShearMismatch: true}
	if _, err := c.Build(); err == nil {
		t.Fatal("server-only flag accepted in client config")
	}
}
