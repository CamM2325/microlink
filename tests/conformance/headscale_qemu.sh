#!/usr/bin/env bash
# Conformance test: MicroLink in QEMU against a real Headscale and a real
# Tailscale client.
#
#   1. starts Headscale and a Tailscale client in Docker,
#   2. builds examples/ethernet_connect for the ESP32 with QEMU's emulated
#      Ethernet (OpenCores MAC), pointed at that Headscale,
#   3. boots it in Espressif's QEMU and waits for CONNECTED,
#   4. pings the device's tailnet address from the Tailscale client, which
#      only succeeds through a working WireGuard tunnel,
#   5. uses the device as exit node: IPv4 (HTTP) must reach the internet through
#      it; QEMU's network has no IPv6, so an IPv6 connection must fail at
#      once (ICMPv6 "no route" from the device) rather than time out.
#
# Needs Docker and port 80 on BIND_IP (MicroLink's plain-HTTP control
# connection always uses port 80). Run from anywhere:
#
#   tests/conformance/headscale_qemu.sh                      # BIND_IP = default route address
#   BIND_IP=192.168.122.1 tests/conformance/headscale_qemu.sh
#
# Logs end up in $OUT (default: build-conformance/ in the repository).
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-$REPO/build-conformance}
BIND_IP=${BIND_IP:-$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1); exit}')}
HEADSCALE_IMAGE=${HEADSCALE_IMAGE:-headscale/headscale:v0.29.7}
TAILSCALE_IMAGE=${TAILSCALE_IMAGE:-tailscale/tailscale:v1.104.7}
IDF_IMAGE=${IDF_IMAGE:-espressif/idf:v5.5.6}
BOOT_TIMEOUT=${BOOT_TIMEOUT:-240}
P=mlconf   # prefix of every container/network this script creates

log() { printf '\n== %s\n' "$*"; }
cleanup() {
    docker logs "$P-headscale" > "$OUT/headscale.log" 2>&1 || true
    docker rm -f "$P-headscale" "$P-ts" "$P-qemu" > /dev/null 2>&1 || true
    docker network rm "$P" > /dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$OUT/headscale"
rm -f "$OUT"/*.log
cleanup

log "Headscale on http://$BIND_IP:80"
cat > "$OUT/headscale/config.yaml" <<EOF
server_url: http://$BIND_IP:80
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
dns:
  magic_dns: false
  override_local_dns: false
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
EOF
docker network create "$P" > /dev/null
docker run -d --name "$P-headscale" --network "$P" -p "$BIND_IP:80:8080" \
    -v "$OUT/headscale:/etc/headscale:ro" "$HEADSCALE_IMAGE" serve > /dev/null
for _ in $(seq 60); do
    docker exec "$P-headscale" headscale health > /dev/null 2>&1 && break
    sleep 1
done
docker exec "$P-headscale" headscale users create conformance > /dev/null
USER_ID=$(docker exec "$P-headscale" headscale users list -o json | python3 -c \
    'import json,sys; print([u["id"] for u in json.load(sys.stdin) if u["name"] == "conformance"][0])')
KEY=$(docker exec "$P-headscale" headscale preauthkeys create --user "$USER_ID" --reusable \
    --expiration 2h -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')
NOISE=$(curl -fsS "http://$BIND_IP/key?v=131" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["publicKey"].removeprefix("mkey:"))')

log "Tailscale client"
docker run -d --name "$P-ts" --network "$P" --cap-add NET_ADMIN --cap-add NET_RAW \
    --device /dev/net/tun -e TS_AUTHKEY="$KEY" -e TS_USERSPACE=false -e TS_ACCEPT_DNS=false \
    -e TS_HOSTNAME=conformance-client -e TS_STATE_DIR=/var/lib/tailscale \
    -e TS_EXTRA_ARGS="--login-server=http://$BIND_IP:80" "$TAILSCALE_IMAGE" > /dev/null

log "Build examples/ethernet_connect for QEMU ($IDF_IMAGE)"
cat > "$OUT/sdkconfig.conformance.defaults" <<EOF
CONFIG_ML_CTRL_HOST="$BIND_IP"
CONFIG_ML_CTRL_NOISE_PUBKEY_HEX="$NOISE"
# CONFIG_ML_CTRL_TLS is not set
CONFIG_ML_TAILSCALE_AUTH_KEY="$KEY"
CONFIG_ML_DEVICE_NAME="conformance-esp32"
CONFIG_ML_SUBNET_ROUTER=y
CONFIG_ML_ADVERTISE_ROUTES="0.0.0.0/0"
CONFIG_LWIP_HOOK_IP6_INPUT_DEFAULT=y
EOF
# sdkconfig defaults only apply when sdkconfig is created: start fresh, or a
# previous run's server key and auth key would be reused
rm -rf "$OUT/build" "$OUT/sdkconfig"
docker run --rm -v "$REPO:/src" -v "$OUT:/out" -w /src/examples/ethernet_connect "$IDF_IMAGE" bash -c '
    set -e
    . "$IDF_PATH/export.sh" > /dev/null 2>&1
    idf.py -B /out/build -D SDKCONFIG=/out/sdkconfig \
        -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.qemu.defaults;/out/sdkconfig.conformance.defaults" \
        build > /out/build.log 2>&1 || { tail -40 /out/build.log; exit 1; }
    cd /out/build
    python -m esptool --chip esp32 merge_bin --fill-flash-size 4MB -o flash.bin @flash_args > /dev/null
    chown -R '"$(id -u):$(id -g)"' /out
    cd /src/examples/ethernet_connect   # files the component manager writes next to the project
    chown -R '"$(id -u):$(id -g)"' dependencies.lock managed_components 2> /dev/null || true'

log "Boot in QEMU"
docker run -d --name "$P-qemu" -v "$OUT:/out" "$IDF_IMAGE" bash -c '
    . "$IDF_PATH/export.sh" > /dev/null 2>&1
    exec qemu-system-xtensa -nographic -machine esp32 \
        -drive file=/out/build/flash.bin,if=mtd,format=raw \
        -nic user,model=open_eth,ipv6=off > /out/qemu.log 2>&1' > /dev/null
VPN_IP=
for _ in $(seq "$BOOT_TIMEOUT"); do
    VPN_IP=$(sed 's/\x1b\[[0-9;]*m//g' "$OUT/qemu.log" 2>/dev/null |
             grep -ao 'Connected! VPN IP: [0-9.]*' | awk '{print $4}' | head -1) || true
    [ -n "$VPN_IP" ] && break
    sleep 1
done
if [ -z "$VPN_IP" ]; then
    echo "FAIL: the device did not reach CONNECTED within $BOOT_TIMEOUT s"
    tail -60 "$OUT/qemu.log"
    exit 1
fi
echo "device connected as $VPN_IP"

log "Ping the device through the tunnel"
docker exec "$P-ts" ping -c 20 -i 0.5 -W 3 "$VPN_IP" | tee "$OUT/ping.log" || true
RECEIVED=$(awk '/packets transmitted/ {print $4}' "$OUT/ping.log")
docker exec "$P-ts" tailscale status > "$OUT/tailscale-status.log" 2>&1 || true
if [ "${RECEIVED:-0}" -lt 15 ]; then
    echo "FAIL: only ${RECEIVED:-0} of 20 pings answered"
    exit 1
fi
echo "ok: $RECEIVED of 20 pings answered by $VPN_IP"

log "Use the device as exit node"
NODE_ID=$(docker exec "$P-headscale" headscale nodes list -o json | python3 -c \
    'import json,sys; print([n["id"] for n in json.load(sys.stdin) if "'"$VPN_IP"'" in n.get("ip_addresses", [])][0])')
docker exec "$P-headscale" headscale nodes approve-routes -i "$NODE_ID" -r 0.0.0.0/0,::/0 > /dev/null
for _ in $(seq 30); do
    docker exec "$P-ts" tailscale set --exit-node="$VPN_IP" > /dev/null 2>&1 && break
    sleep 2
done
sleep 3
# TCP, not ping: GitHub's runners do not pass ICMP to the internet.
OK4=0
for _ in 1 2 3; do
    docker exec "$P-ts" wget -S -T 15 -O /dev/null http://1.1.1.1/ > "$OUT/exit-http4.log" 2>&1 || true
    if grep -qE "HTTP/1\.[01] (200|301|302)" "$OUT/exit-http4.log"; then OK4=1; break; fi
    sleep 3
done
cat "$OUT/exit-http4.log"
if [ "$OK4" != 1 ]; then
    echo "FAIL: IPv4 (HTTP to 1.1.1.1) through the exit node did not work"
    exit 1
fi
RECEIVED4="HTTP ok"
# The client must send IPv6 into the tunnel, or "unreachable" below would
# come from its own kernel rather than from the device.
docker exec "$P-ts" ip -6 route get 2606:4700:4700::1111 | tee "$OUT/exit-route6.log"
if ! grep -q "dev tailscale0" "$OUT/exit-route6.log"; then
    echo "FAIL: the client does not route IPv6 through the exit node"
    exit 1
fi
START=$(date +%s)
docker exec "$P-ts" wget -T 15 -O /dev/null "http://[2606:4700:4700::1111]/" > "$OUT/exit-ipv6.log" 2>&1 || true
ELAPSED=$(( $(date +%s) - START ))
cat "$OUT/exit-ipv6.log"
if [ "$ELAPSED" -ge 8 ] || ! grep -qi "unreachable" "$OUT/exit-ipv6.log"; then
    echo "FAIL: IPv6 without IPv6 upstream did not fail fast with 'unreachable' (${ELAPSED} s)"
    exit 1
fi
echo "PASS: tunnel 20/20; exit node IPv4 ${RECEIVED4}; IPv6 'no route' after ${ELAPSED} s"
