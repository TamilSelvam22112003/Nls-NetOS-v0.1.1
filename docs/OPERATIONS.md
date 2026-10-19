# NLS NetOS operations

## Service lifecycle

```sh
sudo systemctl start nls-router
sudo systemctl stop nls-router
sudo systemctl restart nls-router
systemctl is-active nls-router
journalctl -u nls-router -f
```

The service is not enabled by the installer. Start it only after configuring the CA address and TLS identity, installing the CA certificate and fingerprint, and securely provisioning the router certificate and private key.

## Configuration and secrets

- `/etc/nls-router/router.env`: root-owned configuration, group-readable by `nls-router`.
- `/etc/nls-router/router-key.pem`: private key should be root-owned and mode `0640` with group `nls-router`, or use a stricter key-delivery method supported by your deployment.
- `/var/lib/nls-router`: persistent accepted policy/revocation state; do not delete during routine upgrades.
- Never put enrollment tokens or private keys in command-line arguments, shell history, tickets, or logs.

After changing config, restart the service and inspect logs. If the CA endpoint is unavailable, inspect routing, DNS/TLS name, root certificate pin, client certificate validity, and CA-side authorization before relaxing any verification.

## Failure behavior and limitations

The control client has a configurable control-loss timeout (default five minutes). The intended security posture is fail closed when control state becomes stale. Verify this behavior against the exact deployed build and test it before production use.

This branch is not a production-ready NLS router: handshake code derives keys but does not install them into a live data plane. The unit is a control-client service, not a packet-forwarding/TUN service. Do not claim protected traffic, revocation enforcement on packets, or production readiness based only on this service starting.

## Upgrade and rollback

Build and test a candidate binary first. Stop the service before replacing the binary; preserve `/etc/nls-router` and `/var/lib/nls-router`. Keep a checksum and known-good binary for rollback. Review release notes and rerun the target VM install/uninstall checks before upgrading.

## Diagnostics

```sh
systemctl status nls-router --no-pager
journalctl -u nls-router -b --no-pager
/usr/local/sbin/nls-router help
stat -c '%U:%G %a %n' /etc/nls-router/router.env /var/lib/nls-router
```
