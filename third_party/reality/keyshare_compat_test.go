package reality

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestRealityKeyShareCompatibility(t *testing.T) {
	x := keyShare{group: X25519, data: bytes.Repeat([]byte{1}, 32)}
	h := keyShare{group: X25519MLKEM768, data: bytes.Repeat([]byte{2}, mlkem.EncapsulationKeySize768+32)}
	for _, tc := range []struct {
		name           string
		shares         []keyShare
		strict, compat []byte
	}{
		{"ios", []keyShare{x}, nil, x.data},
		{"chrome", []keyShare{h, x}, x.data, x.data},
		{"hybrid-only", []keyShare{h}, h.data[mlkem.EncapsulationKeySize768:], h.data[mlkem.EncapsulationKeySize768:]},
		{"wrong-order", []keyShare{x, h}, nil, x.data},
		{"duplicate-hybrid", []keyShare{h, h, x}, nil, x.data},
		{"empty", nil, nil, nil},
		{"bad-lengths", []keyShare{{group: X25519, data: []byte{1}}, {group: X25519MLKEM768, data: []byte{2}}}, nil, nil},
		{"unrelated-group", []keyShare{{group: CurveP256, data: x.data}}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []struct {
				enabled bool
				want    []byte
			}{{false, tc.strict}, {true, tc.compat}, {false, tc.strict}} {
				if got := realityClientKeyShare(tc.shares, mode.enabled); !bytes.Equal(got, mode.want) {
					t.Fatalf("enabled=%v: got %x, want %x", mode.enabled, got, mode.want)
				}
			}
		})
	}
}

func TestRealityConfigCloneCompatibility(t *testing.T) {
	strict := &Config{}
	compat := &Config{IgnoreClientHelloKeyShearMismatch: true}
	if !compat.Clone().IgnoreClientHelloKeyShearMismatch || strict.Clone().IgnoreClientHelloKeyShearMismatch {
		t.Fatal("per-listener compatibility flag lost or leaked during Clone")
	}
}
