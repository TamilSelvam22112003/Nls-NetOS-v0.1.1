#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-install}"
PREFIX=/usr/local
CONFIG_DIR=/etc/nls-router
STATE_DIR=/var/lib/nls-router
UNIT_DIR=/etc/systemd/system
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"

case "$ACTION" in install|uninstall) ;; *) echo "usage: $0 [install|uninstall]" >&2; exit 2;; esac
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

if [[ "$ACTION" == uninstall ]]; then
  systemctl disable --now nls-router.service 2>/dev/null || true
  rm -f "$UNIT_DIR/nls-router.service" "$PREFIX/libexec/nls-router-control" "$PREFIX/sbin/nls-router"
  systemctl daemon-reload
  systemctl reset-failed nls-router.service 2>/dev/null || true
  echo "Uninstalled NLS router binaries and unit. Config/state retained at $CONFIG_DIR and $STATE_DIR."
  if [[ "${PURGE_NLS_ROUTER:-0}" == 1 ]]; then
    rm -rf "$CONFIG_DIR" "$STATE_DIR"
    echo "PURGE_NLS_ROUTER=1: removed config and state."
  fi
  exit 0
fi

case "$ARCH" in amd64) GOARCH=amd64;; arm64) GOARCH=arm64;; *) echo "unsupported architecture: $ARCH (supported: amd64, arm64)" >&2; exit 1;; esac
command -v go >/dev/null 2>&1 || { echo "Go is required to build; install Go 1.22+" >&2; exit 1; }
make -C "$ROOT_DIR" build GOOS=linux GOARCH="$GOARCH"
install -d -o root -g root -m 0755 "$PREFIX/sbin" "$PREFIX/libexec" "$CONFIG_DIR" "$UNIT_DIR"
if ! id nls-router >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin nls-router
fi
install -d -o nls-router -g nls-router -m 0750 "$STATE_DIR"
install -o root -g root -m 0755 "$ROOT_DIR/bin/nls-router" "$PREFIX/sbin/nls-router"
install -o root -g root -m 0755 "$ROOT_DIR/scripts/nls-router-control" "$PREFIX/libexec/nls-router-control"
install -o root -g root -m 0644 "$ROOT_DIR/systemd/nls-router.service" "$UNIT_DIR/nls-router.service"
if [[ ! -e "$CONFIG_DIR/router.env" ]]; then
  install -o root -g nls-router -m 0640 "$ROOT_DIR/config/router.env.example" "$CONFIG_DIR/router.env"
  echo "Created $CONFIG_DIR/router.env. Edit its values and install router certificate/key before starting the service."
else
  chown root:nls-router "$CONFIG_DIR/router.env"
  chmod 0640 "$CONFIG_DIR/router.env"
fi
systemctl daemon-reload
echo "Installed static router binary. Service is NOT enabled or started automatically."
echo "Before starting: configure $CONFIG_DIR/router.env and securely install CA/router credentials."
echo "Then run: systemctl enable --now nls-router.service"
