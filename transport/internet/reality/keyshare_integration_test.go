package reality_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	nativereality "github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

// Exercise two live listeners simultaneously, including ML-DSA certificate
// verification and an application-data round trip. No public target is used.
func TestKeyShareCompatibilityListenerIsolation(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	target.StartTLS()
	// REALITY mirrors the target record sizes. Give the synthetic target enough
	// certificate-chain space for the ML-DSA-65 extension (3309 signature bytes).
	leaf := target.TLS.Certificates[0].Certificate[0]
	target.TLS.Certificates[0].Certificate = [][]byte{leaf, leaf, leaf, leaf, leaf, leaf}
	// This local target has tickets disabled and emits no post-handshake records.
	for _, alpn := range []string{"0", "1", "2"} {
		key := target.Listener.Addr().String() + " example.com " + alpn
		nativereality.GlobalPostHandshakeRecordsLens.Store(key, []int{})
		t.Cleanup(func() { nativereality.GlobalPostHandshakeRecordsLens.Delete(key) })
	}
	defer target.Close()

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{42}, 32)
	mldsaKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		t.Fatal(err)
	}
	shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	listen := func(compat bool) string {
		c := (&xreality.Config{
			Type: "tcp", Dest: target.Listener.Addr().String(),
			ServerNames: []string{"example.com"}, PrivateKey: key.Bytes(),
			ShortIds: [][]byte{shortID}, Mldsa65Seed: seed,
			IgnoreClientHelloKeyShearMismatch: compat,
		}).GetREALITYConfig()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer raw.Close()
					raw.SetDeadline(time.Now().Add(5 * time.Second))
					conn, err := nativereality.Server(context.Background(), raw, c)
					if err != nil {
						return
					}
					defer conn.Close()
					b := make([]byte, 4)
					if _, err := io.ReadFull(conn, b); err == nil {
						conn.Write(b)
					}
				}()
			}
		}()
		return ln.Addr().String()
	}
	compatAddr, strictAddr := listen(true), listen(false)
	for _, tc := range []struct {
		name, addr, fingerprint, bad string
		ok                           bool
	}{
		{"compat-ios", compatAddr, "ios", "", true},
		{"strict-ios", strictAddr, "ios", "", false},
		{"strict-chrome", strictAddr, "chrome", "", true},
		{"compat-chrome", compatAddr, "chrome", "", true},
		{"compat-ios-wrong-short-id", compatAddr, "ios", "short-id", false},
		{"compat-ios-wrong-public-key", compatAddr, "ios", "public-key", false},
		{"compat-ios-wrong-server-name", compatAddr, "ios", "server-name", false},
		{"compat-ios-wrong-mldsa", compatAddr, "ios", "mldsa", false},
		{"strict-ios-still-rejected", strictAddr, "ios", "", false},
		{"compat-ios-still-accepted", compatAddr, "ios", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &xreality.Config{Fingerprint: tc.fingerprint, ServerName: "example.com", PublicKey: key.PublicKey().Bytes(), ShortId: shortID, Mldsa65Verify: mldsaKey.PublicKey().Bytes(), SpiderX: "/", SpiderY: make([]int64, 10)}
			switch tc.bad {
			case "short-id":
				cfg.ShortId = make([]byte, 8)
			case "public-key":
				k, e := ecdh.X25519().GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				cfg.PublicKey = k.PublicKey().Bytes()
			case "server-name":
				cfg.ServerName = "other.example.com"
			case "mldsa":
				k, e := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{43}, 32))
				if e != nil {
					t.Fatal(e)
				}
				cfg.Mldsa65Verify = k.PublicKey().Bytes()
			}
			raw, err := net.DialTimeout("tcp", tc.addr, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(5 * time.Second))
			dest, err := xnet.ParseDestination("tcp:" + tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := xreality.UClient(raw, cfg, context.Background(), dest)
			if !tc.ok {
				if err == nil {
					conn.Close()
					t.Fatal("unexpected authenticated connection")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err = conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 4)
			if _, err = io.ReadFull(conn, b); err != nil {
				t.Fatal(err)
			}
			if string(b) != "ping" {
				t.Fatalf("unexpected echo: %q", b)
			}
		})
	}
}
