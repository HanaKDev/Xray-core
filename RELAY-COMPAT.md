# Per-inbound REALITY relay compatibility

Based on Xray-core `92ccc939aaf4f8965f369cf0b142e005aeaa11d5` (26.10.17).

## Configuration

Set this **only inside the selected inbound's `streamSettings.realitySettings`**:

```jsonc
"ignoreClientHelloKeyShearMismatch": true
```

The spelling `KeyShear` is intentional and matches the requested configuration
API. Omitted or `false` retains the upstream ClientHello key-share requirements.
Every inbound has its own value; enabling one listener does not alter any other
listener, existing configuration object, or global policy. Enabling this option
in REALITY client configuration is rejected.

`true` restores pre-2026-09-08 key-share selection: prefer a valid X25519 share,
otherwise use the X25519 component of a valid X25519MLKEM768 share. This permits
legacy `ios` ClientHellos and different share ordering. It does not bypass
REALITY authentication, SNI, short ID, configured version/time checks, or
ML-DSA certificate verification. It does not add a hybrid key exchange to the
old iOS fingerprint. Existing VLESS Encryption settings remain independent.

## Dependency changes

- The REALITY source at `83f621788ca8` is included under `third_party/reality`
  through a local module replacement so a clean clone can reproduce the build.
  Its upstream licenses are retained. Changes are limited to a per-config bool,
  `Config.Clone`, key-share selection, and regression tests.
- uTLS is pinned to `v1.8.3-0.20261006222701-ff1b50fbbe9a`. Upstream had 177 commits
  after the old pin when checked on 2026-10-18 JST. Its latest tagged release was
  still v1.8.2; this pin intentionally uses a newer upstream development commit.
  `chrome` now maps to Chrome 155; `ios` remains iOS 14.
- The updated uTLS dependency brings `go-brrr` and klauspost/compress v1.20.1.

## Tests

```sh
go test ./infra/conf ./transport/internet/reality github.com/xtls/reality \
  -run 'TestREALITY.*KeyShare|TestReality(KeyShare|ConfigClone)|TestKeyShareCompatibilityListenerIsolation' -count=1
go test -race ./infra/conf ./transport/internet/reality github.com/xtls/reality \
  -run 'TestREALITY.*KeyShare|TestReality(KeyShare|ConfigClone)|TestKeyShareCompatibilityListenerIsolation' -count=1
```

The integration test uses two simultaneous local REALITY listeners and a local
TLS target, retaining ML-DSA-65 verification. It checks legacy iOS acceptance only
on the opted-in listener, Chrome acceptance on both, an application-data echo,
and rejection of wrong public key, short ID, SNI, and ML-DSA verification key.
Tests use synthetic credentials only.

The unfiltered upstream infra/conf suite requires external geodata files, and
the TLS suite performs public-network ECH/DNS requests. Those suites were not
fully validated in the restricted build environment; the local regression and
race tests above are the acceptance gate for this change.

## Static Linux amd64 build

Use Go 1.27.2 and the repository-pinned dependencies:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -buildvcs=false -gcflags='all=-l=4' \
  -ldflags="-s -w -buildid= -X github.com/xtls/xray-core/core.build=$(git rev-parse --short HEAD)-relaycompat" \
  -o xray-linux-amd64 ./main
```

GOAMD64=v1 retains compatibility with older x86-64 machines. Verify static linkage
with `file` and `readelf -l`; no ELF interpreter or NEEDED shared library is
expected. Production configuration files and private keys are not in this repo.
