# Cathode integration (opt-in)

This branch extends the upstream core for Cathode's initial small deployment release. The existing per-inbound REALITY ignoreClientHelloKeyShearMismatch option remains isolated per listener. Normal operation without the journal environment variable retains ordinary in-memory statistics.

## Durable counter source

Set XRAY_CATHODE_USAGE_JOURNAL to a private persistent file; enable stats and level 0 statsUserUplink/statsUserDownlink. Positive user counter events are CRC-framed and synchronously fsynced before updating cumulative state. UTC+8 collection dates and a stable ledger ID survive core restarts. Incomplete final lines are truncated; corrupt committed records reject startup. A second writer is rejected.

At roughly 64MiB, the next event atomically compacts into equivalent per-day/email/direction totals, retaining the ledger ID. File and directory synchronization and old/new inode locks protect replacement. A 1GiB hard bound, I/O failure or failed compaction fails the process rather than silently losing source accounting. No automatic retention deletion. Sync I/O has not been throughput benchmarked. This guarantees recoverability of committed Counter.Add events, not exact wire bytes during a crash between network forwarding and counter recording. Public reset requests are rejected while durable accounting is active.

## Management RPC

HandlerService registers /cathode.core.v1.Management/Call. Both sides use protobuf google.protobuf.BytesValue; the bytes contain a JSON envelope. The existing core API must be private loopback, never exposed to untrusted clients. Operations:

- usage: durable cumulative dated source snapshot with ledger, journal_bytes/journal_limit.
- snapshot: boot, revision, build, running executable SHA256, reconstructed core.Config PB, locks and explicit coverage. Active validators and router are exported; static retained configuration is cloned from startup. Loaded assets, hot certificate contents and transient balancer state are not fingerprinted.
- compare: config_pb from the identical core binary's convert pb. Expands TypedMessage semantically, normalizes supported user representation, retains rule/outbound semantics, returns differing field paths without values. equal=true means covered configuration matches; state=partial-match and unverified remain explicit. It is not a complete process-memory export.
- route_apply: config_pb plus boot/revision and explicit unlock/lock ruleTag lists. Only routing is replaced, never bootstrap. Rejects stale state, scripts, domain strategy changes and missing direct outbound references.

XRAY_CATHODE_LOCKED_RULES is a comma-separated initial ruleTag list. Missing tags fail startup. Locked rules must retain their exact protobuf and position; explicit unlock permits a privileged transaction to reorder, then relock. Existing routing API writes share the guard. All public handler/routing writes share the core management mutex for consistent managed snapshots. Host-level access or arbitrary internal plugins are outside this protection.

For a complete operations guide, release scope and counting boundary see StarHanami/Cathode docs. This source remains MPL-2.0; dependencies retain their own licenses. Do not describe the directed regression suite as a complete upstream test pass.

The reconstructed outbound config excludes synthetic commander and metrics service handlers; their feature configs remain in app settings. Enabling metrics must not produce a spurious extra outbound or a nil proxy config in semantic comparisons. Do not reuse a routed API/metrics tag; an independent loopback API listen address can coexist with existing metrics routing.
