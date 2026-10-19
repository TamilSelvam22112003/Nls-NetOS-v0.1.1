# Data plane implementation notes

The `internal/dataplane` package implements the frozen NLS data datagram format, authenticated encryption, replay tracking, session rekey APIs, prefix policy selection, Linux TUN creation, protected route installation, and MSS clamping.

- Data packets use common framing + the 32-byte NLS data header + AES-256-GCM ciphertext/tag. The common header and data header are AAD.
- Send sequence numbers start at 1; the nonce is the 4-byte directional salt followed by the 64-bit sequence.
- The receiver commits replay-window state only after GCM authentication and inner IP packet validation. The replay window is 1024 packets.
- Unknown policy, a missing PROTECT session, invalid packets, authentication failures, and BYPASS packets encountered on the TUN path are dropped. There is no plaintext fallback.
- Policy updates reject noncanonical prefixes and conflicting overlaps. PROTECT routes are blackholed before being pointed at `nls0`; obsolete protected routes are removed only after the in-memory policy replacement.
- At path MTU 1500, the inner MTU is 1396, IPv4 TCP MSS is 1356 and IPv6 TCP MSS is 1336.

## Integration blocker: session identifiers

`PROTOCOL.md §8` requires a nonzero 16-bit `session_id` and a random 16-byte `session_nonce_id` shared by both routers. The frozen M1–M4 layouts do not carry either value, and §7 does not define derivation labels for them. This package accepts both as explicit session-setup inputs; it does not silently invent a wire field or extend the key schedule.

Before wiring the handshake command directly into a persistent TUN runtime, the protocol owner must decide whether these values are:
1. derived from the existing handshake transcript using new, explicitly specified HKDF labels (with collision handling for the 16-bit ID), or
2. negotiated through a versioned handshake amendment.

## Rekey note

The implementation signs and encrypts REKEY_INIT/ACK, derives replacement directional keys and salts, retransmits an identical REKEY_INIT at most three times within the 3-second window when requested again, and switches keys only after ACK authentication / successful ACK transmission. The exact proposal hash is `SHA256(old_transcript_hash || epoch:u32 || ephemeral_public_key)`; the rekey transcript for replacement-key salt is `SHA256(REKEY_INIT_body || REKEY_ACK_body)`. This deterministic canonicalization is implementation-defined because §9 specifies the fields and salt formula but does not spell out the byte-exact rekey transcript hash. It should be ratified in a protocol erratum before interoperable release.
