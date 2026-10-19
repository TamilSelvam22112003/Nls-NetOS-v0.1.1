# Nls-NetOS-v0.1.1

Ubuntu router client scaffold for the NLS v0.1.1 protocol.

This branch implements router key/CSR generation, pinned TLS 1.3 enrollment,
certificate verification, and an mTLS control client that validates and
persists policy and revocation snapshots. It does not yet implement the TUN
data plane or NLS handshake and is not production-ready.

See docs/PROTOCOL.md for the normative wire contract.

## Router enrollment

```sh
# Generate an Ed25519 key and CSR locally.
nls-router keygen --name router-01 --key-out router-key.pem --csr-out router.csr.pem
# Send the printed public-key SHA-256 to the CA administrator.
# Import the CA certificate and fingerprint through a trusted channel.
export NLS_ENROLLMENT_TOKEN='<one-time-token-from-admin>'
nls-router enroll --address ca.example:8443 --tls-name ca.example \
  --ca-cert ca-cert.pem --ca-fingerprint <sha256-of-ca-cert-der> \
  --name router-01 --key router-key.pem --csr router.csr.pem --cert-out router-cert.pem
unset NLS_ENROLLMENT_TOKEN
```

## Authenticated control

```sh
nls-router control --address ca.example:8444 --tls-name ca.example \
  --ca-cert ca-cert.pem --ca-fingerprint <sha256-of-ca-cert-der> \
  --cert router-cert.pem --key router-key.pem --state-dir /var/lib/nls-router
```

The client requires TLS 1.3, verifies both the CA chain and exact configured
root-certificate SHA-256 pin, uses the issued router certificate for mTLS, and
persists accepted policy/revocation snapshots with restrictive permissions.
