#!/usr/bin/env bash
# NLS namespace end-to-end harness.
#
# Requires Linux root/CAP_NET_ADMIN, iproute2, tcpdump, curl, ping, and an
# integration driver that wires the repository's CA/enrollment/handshake/data
# plane into the namespaces. The current nls-router scaffold does not expose
# that complete runtime yet; the harness refuses to report a false pass.
#
# Driver contract (NLS_E2E_DRIVER executable):
#   ca-start <ca-ns> <ca-ip>
#   router-enroll <router-name> <router-ns> <ca-ip>
#   router-start <router-name> <router-ns> <local-ip> <peer-ip> <server-prefix>
#   handshake <router1-ns> <router2-ns>
#   client-ping <client-ns> <server-ip>
#   client-curl <client-ns> <url>
#   router-revoke <router-name> <ca-ns>
#   assert-revoked <router-name> <router-ns>
# Driver commands must return nonzero on any failure and use the real NLS
# protocol; a plain-IP/UDP fallback is not acceptable.
set -Eeuo pipefail
IFS=$'\n\t'

readonly PREFIX="${NLS_E2E_PREFIX:-nls-e2e}"
readonly CLIENT="${PREFIX}-client"
readonly R1="${PREFIX}-r1"
readonly R2="${PREFIX}-r2"
readonly SERVER="${PREFIX}-server"
readonly CA="${PREFIX}-ca"
readonly WORK="${NLS_E2E_WORKDIR:-/tmp/${PREFIX}}"
readonly WAN_PCAP="${WORK}/wan.pcap"
readonly WAN_TEXT="${WORK}/wan.txt"
readonly SERVER_IP="10.30.0.2"
readonly CLIENT_IP="10.10.0.2"
readonly R1_LAN="10.10.0.1"
readonly R1_WAN="192.0.2.1"
readonly R2_WAN="192.0.2.2"
readonly R2_LAN="10.30.0.1"
readonly CA_IP="10.40.0.2"
readonly SECRET_MARKER="NLS_E2E_CONFIDENTIAL_PAYLOAD_7f4c2a"
readonly DRIVER="${NLS_E2E_DRIVER:-}"

log() { printf '[e2e] %s\n' "$*"; }
die() { printf '[e2e] BLOCKED/FAIL: %s\n' "$*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"; }
ns() { ip netns exec "$1" "${@:2}"; }
exists_ns() { ip netns list | awk '{print $1}' | grep -Fxq "$1"; }

cleanup() {
  set +e
  [[ -n "${CAP_PID:-}" ]] && kill "$CAP_PID" 2>/dev/null
  for n in "$CLIENT" "$R1" "$R2" "$SERVER" "$CA"; do
    ip netns del "$n" 2>/dev/null
  done
  if [[ "${NLS_E2E_KEEP_ARTIFACTS:-0}" != 1 ]]; then
    rm -rf "$WORK"
  else
    log "artifacts retained at $WORK"
  fi
}
trap cleanup EXIT INT TERM

[[ $EUID -eq 0 ]] || die "run as root (Linux network namespaces require CAP_NET_ADMIN)"
for c in ip ping curl tcpdump awk grep timeout sysctl; do need "$c"; done
[[ -n "$DRIVER" && -x "$DRIVER" ]] || die "NLS_E2E_DRIVER must point to an executable integration driver; this branch has no complete CA-to-TUN runtime CLI yet"
mkdir -p "$WORK"
chmod 700 "$WORK"

# Remove leftovers from an interrupted run, without touching unrelated namespaces.
for n in "$CLIENT" "$R1" "$R2" "$SERVER" "$CA"; do ip netns del "$n" 2>/dev/null || true; done
for n in "$CLIENT" "$R1" "$R2" "$SERVER" "$CA"; do ip netns add "$n"; ip -n "$n" link set lo up; done

# Client -- R1 -- R2 -- Server. A separate management link connects CA to R1
# and R2; it is not part of the captured WAN data link.
ip link add e2c type veth peer name e2r1
ip link set e2c netns "$CLIENT"; ip link set e2r1 netns "$R1"
ip link add e2r1w type veth peer name e2r2w
ip link set e2r1w netns "$R1"; ip link set e2r2w netns "$R2"
ip link add e2r2s type veth peer name e2s
ip link set e2r2s netns "$R2"; ip link set e2s netns "$SERVER"
ip link add e2r1m type veth peer name e2ca
ip link set e2r1m netns "$R1"; ip link set e2ca netns "$CA"
ip link add e2r2m type veth peer name e2cam
ip link set e2r2m netns "$R2"; ip link set e2cam netns "$CA"

# Address links. IPv4 documentation ranges are used only inside isolated namespaces.
ns "$CLIENT" ip addr add "$CLIENT_IP/24" dev e2c
ns "$R1" ip addr add "$R1_LAN/24" dev e2r1
ns "$R1" ip addr add "$R1_WAN/30" dev e2r1w
ns "$R2" ip addr add "$R2_WAN/30" dev e2r2w
ns "$R2" ip addr add "$R2_LAN/24" dev e2r2s
ns "$SERVER" ip addr add "$SERVER_IP/24" dev e2s
ns "$R1" ip addr add 10.40.0.1/24 dev e2r1m
ns "$CA" ip addr add "$CA_IP/24" dev e2ca
ns "$R2" ip addr add 10.41.0.1/24 dev e2r2m
ns "$CA" ip addr add 10.41.0.2/24 dev e2cam

for pair in "$CLIENT e2c" "$R1 e2r1" "$R1 e2r1w" "$R1 e2r1m" "$R2 e2r2w" "$R2 e2r2s" "$R2 e2r2m" "$SERVER e2s" "$CA e2ca" "$CA e2cam"; do
  read -r n dev <<< "$pair"; ns "$n" ip link set "$dev" up
done
ns "$CLIENT" ip route add default via "$R1_LAN"
ns "$SERVER" ip route add default via "$R2_LAN"
ns "$R1" sysctl -qw net.ipv4.ip_forward=1
ns "$R2" sysctl -qw net.ipv4.ip_forward=1
ns "$R1" ip route add 10.30.0.0/24 via "$R2_WAN"
ns "$R2" ip route add 10.10.0.0/24 via "$R1_WAN"

log "namespace topology ready: client -> local router -> destination router -> server; CA management links isolated"
log "WAN capture starts on R1/R2 link (e2r1w/e2r2w)"
ns "$R1" tcpdump -U -n -s 0 -i e2r1w -w "$WAN_PCAP" >"$WORK/tcpdump.log" 2>&1 &
CAP_PID=$!
sleep 1

log "starting CA and enrolling both routers"
"$DRIVER" ca-start "$CA" "$CA_IP"
"$DRIVER" router-enroll local-router "$R1" "$CA_IP"
"$DRIVER" router-enroll destination-router "$R2" "$CA_IP"
log "starting protected router dataplanes and establishing NLS handshake"
"$DRIVER" router-start local-router "$R1" "$R1_WAN" "$R2_WAN" "10.30.0.0/24"
"$DRIVER" router-start destination-router "$R2" "$R2_WAN" "$R1_WAN" "10.10.0.0/24"
"$DRIVER" handshake "$R1" "$R2"

log "checking client-to-server ICMP"
timeout 15 "$DRIVER" client-ping "$CLIENT" "$SERVER_IP"
log "checking client-to-server HTTP payload confidentiality"
timeout 20 "$DRIVER" client-curl "$CLIENT" "http://$SERVER_IP/$SECRET_MARKER"

# Stop capture before inspecting it.
kill "$CAP_PID" 2>/dev/null || true
wait "$CAP_PID" 2>/dev/null || true
unset CAP_PID
tcpdump -nn -A -r "$WAN_PCAP" >"$WAN_TEXT" 2>"$WORK/tcpdump-read.log" || die "could not decode WAN capture"
if grep -Fq "$CLIENT_IP" "$WAN_TEXT" || grep -Fq "$SERVER_IP" "$WAN_TEXT"; then
  cat "$WAN_TEXT"
  die "inner client/server IP visible in WAN capture"
fi
if grep -Fq "$SECRET_MARKER" "$WAN_TEXT"; then
  cat "$WAN_TEXT"
  die "HTTP payload marker visible in WAN capture"
fi
log "PASS: inner IP addresses and test payload marker not found in WAN packet decode"
log "capture summary:"
tcpdump -nn -r "$WAN_PCAP" 2>&1 | tee "$WORK/capture-summary.txt" || true

log "revoking local-router certificate and asserting fail-closed traffic stop"
"$DRIVER" router-revoke local-router "$CA"
"$DRIVER" assert-revoked local-router "$R1"
if timeout 8 "$DRIVER" client-ping "$CLIENT" "$SERVER_IP"; then
  die "traffic still succeeded after router revocation"
fi
if timeout 8 "$DRIVER" client-curl "$CLIENT" "http://$SERVER_IP/$SECRET_MARKER"; then
  die "HTTP traffic still succeeded after router revocation"
fi
log "PASS: ICMP and HTTP both stopped after revocation"
log "PASS: namespace NLS e2e checks completed"
log "Artifacts: $WAN_PCAP $WAN_TEXT"
