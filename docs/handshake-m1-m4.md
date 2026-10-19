# NLS v1 M1–M4 implementation

This package implements the frozen sequence in PROTOCOL.md §§6–7 and ADR-0012/0013:

`M1_INIT → M1_COOKIE → M1_INIT(cookie) → M2 → M3 → M4`

## Runtime entry points

- `Initiate` obtains a temporary IPv6 vIP from a `VIPProvider`, binds the M1 socket to that address and the local RDR's advertised UDP port, performs the exchange, verifies M4, and releases the vIP/socket before returning a session.
- `Responder.Serve` handles M1 and M3. The first M1 gets a stateless cookie only; pending state is allocated only after a valid cookie. The listener must bind a specific IPv6 endpoint corresponding to the local RDR.
- `LinuxVIPProvider` assigns a random interface ID within the configured routed prefix, waits for DAD, installs an IPv6 firewall accept rule for the handshake UDP port followed by a drop rule for other traffic to that vIP, binds the UDP socket, and removes the rules/address on cleanup.
- Both roles use `PeerDirectory.LookupForHandshake`; this must be backed by the online CA client. A cache-only lookup is not sufficient.
- Session key schedule uses one X25519 shared secret and independent HKDF-SHA256 expansions with each exact `NLS-v1 ...` label plus TH0. Identity encryption uses one-use AES-256-GCM keys and the all-zero 12-byte handshake nonce; data keys and 4-byte direction salts are separate.

## Required configuration

No unassigned policy defaults are invented. A responder must explicitly configure global, per-ingress-interface, and per-source-/64 M1 token-bucket rates/bursts, the ingress-interface allowlist, tracked-prefix cap, pending-state limits, and pending-state TTL. The accepted protocol default for pending M3 wait is 3 seconds; the configured TTL should be set to that value unless the protocol owner changes it.

The Linux vIP provider requires explicit DAD timeout and polling interval because ADR-0005 does not state numeric values. It requires Linux `ip` and `ip6tables`, privilege to add/remove IPv6 addresses and firewall rules, a routed WAN prefix no longer than /64, a WAN address inside that prefix, and the router's advertised UDP port. IPv4-only WAN is unsupported.

## Cookie transcript reconstruction

M1_COOKIE carries the 10-minute bucket, while M1_INIT(cookie) carries only the 16-byte cookie. The responder verifies the cookie against the current and previous buckets and recovers the matching bucket; it can then reconstruct the exact initial M1 and M1_COOKIE bytes for TH0 without storing state for the first M1. This preserves the specified stateless challenge.

## Limits and integration boundary

- RDR verification, fresh online lookup, revoked/stale peer rejection, M2/M3 transcript signatures, identity encryption, M4 finish MAC, directional keys, and vIP cleanup are implemented in this package.
- The handshake API returns session keys but does not yet install them into a data-plane session manager or route protected packets. The existing data-plane package remains scaffolding.
- M1 limiter rates/bursts and vIP DAD timing are intentionally explicit runtime configuration; the protocol documents their categories but does not assign numeric values.
- The frozen bespoke SIGMA-I-style encoding still requires the independent cryptographic review called out in PROTOCOL.md before production deployment.
