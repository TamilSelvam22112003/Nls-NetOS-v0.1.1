# NLS NetOS installation (Ubuntu 22.04)

## Scope and prerequisites

This installs the **router CLI and its control-client systemd unit**. It does not install a complete NLS data-plane daemon: the current CLI explicitly reports that handshake-derived keys are not installed for traffic. The CA control server must also exist and expose the protocol expected by the router before the service can become healthy.

Supported build targets in this script: Ubuntu/Debian `amd64` and `arm64`. Build from a checkout of branch `feat/handshake-m1-m4`, with Go 1.22+ and make installed.

## Build a static Linux binary

```sh
make clean
make build GOOS=linux GOARCH=amd64
file bin/nls-router
ldd bin/nls-router
```

The build uses `CGO_ENABLED=0`, `-trimpath`, and a single main package. A static Go binary normally causes `ldd` to report that it is not a dynamic executable. Verify this on the target architecture; do not copy an amd64 binary to arm64.

## Install

```sh
sudo apt-get update
sudo apt-get install -y golang-go make
sudo ./scripts/install-router.sh install
sudoedit /etc/nls-router/router.env
```

Copy the Router-CA root certificate to the configured `CA_CERT` path, calculate its DER SHA-256 fingerprint through a trusted procedure, and install the issued router certificate and private key at `ROUTER_CERT` and `ROUTER_KEY`. Protect the private key (root-owned and readable only by the service account). Ensure the TLS name matches the CA certificate. Do not use the example fingerprint or `.invalid` TLS name.

The installer creates the `nls-router` system user, persistent state directory, binary, wrapper, unit, and default config. It does not enable the service automatically because the example configuration is intentionally unusable until provisioned.

## Start and verify

```sh
sudo systemctl enable --now nls-router.service
systemctl --no-pager --full status nls-router.service
journalctl -u nls-router.service -b --no-pager
```

The current router service runs the authenticated control client. It requires a compatible live CA control endpoint; this repository branch does not itself provide a working CA network daemon or a complete protected TUN data path.

## Uninstall

```sh
sudo ./scripts/install-router.sh uninstall
```

Uninstall stops/disables the unit and removes the installed binary, wrapper, and unit. It deliberately preserves `/etc/nls-router` and `/var/lib/nls-router`. To delete those too, explicitly run:

```sh
sudo PURGE_NLS_ROUTER=1 ./scripts/install-router.sh uninstall
```

This purge is destructive. Back up certificates and state first.
