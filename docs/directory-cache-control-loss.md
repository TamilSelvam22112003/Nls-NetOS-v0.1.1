# Router directory cache and CA control-loss behavior

This document records the implementation of accepted ADR-0007 and the boundaries that remain unspecified. It introduces no new availability policy.

## Enforced behavior

- A new handshake must call directory.Cache.LookupForHandshake; it always contacts the CA lookup function even if the requested RDR is cached.
- A CA transport failure, malformed lookup response, or status UNAVAILABLE denies that handshake. The cache is never an authorization fallback.
- UNKNOWN and REVOKED are distinct failures. A returned RDR must be exactly 322 bytes, canonical under the frozen v1 layout, signed with the NLS-v1-RDR context by the pinned Router-CA Ed25519 key, status ACTIVE, within its validity interval, and bound to the requested router ID.
- The in-memory cache retains verified RDRs for at most the configured TTL (default 300 seconds). Its diagnostic getter is not a handshake authorization API.
- The control client publishes control-health state and retries failed control connections. The loss guard marks existing sessions for teardown only after control loss is strictly greater than the configured threshold (default 300 seconds), matching “>300s” in ADR-0007.
- No plaintext fallback is introduced. Protected routing remains fail-closed when policy, directory authorization, or session state is absent.

## Open decisions — not inferred by this implementation

1. Cache persistence: ADR-0007 specifies TTL but does not say whether the RDR cache survives router process restart. This implementation uses an in-memory cache.
2. Cache timestamp source across restarts: no persisted-cache timestamp/clock rollback rule is defined. The in-memory cache rejects clock rollback relative to its fetch time.
3. Control-loss timer origin: this implementation measures from the last successfully completed heartbeat plus policy/revocation synchronization. The spec does not explicitly define whether a failed partial sync starts control loss at last heartbeat ACK or last complete sync.
4. No initial control success: the spec does not define alert/retry cadence before the first successful control session. No existing sessions can be preserved across a fresh process start; retries use the configured sync interval.
5. Revocation push during outage: the 30-second teardown deadline is implementable when a revocation is received. The spec does not define how to learn a revocation that occurs while the CA is unreachable; the 300-second control-loss rule remains the specified bound for existing sessions.
6. Timeout configuration source: the protocol says TTL and loss thresholds are configurable but does not define a configuration file/CLI schema or whether live changes apply to existing timers. This implementation exposes values as API options with specified defaults.
7. Lookup retry policy: the protocol defines UNAVAILABLE but no retry-after/backoff field for directory responses. Each lookup fails closed; caller retry cadence remains caller-controlled.
8. Freshness boundary: the cache diagnostic getter treats age equal to TTL as valid and greater than TTL as stale. The protocol does not define inclusive/exclusive equality; this applies only to diagnostic cache reads, never handshake authorization.
