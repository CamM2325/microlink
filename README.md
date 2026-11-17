# MicroLink

An unofficial, Tailscale-compatible VPN client for ESP32, packaged as an ESP-IDF component.
MicroLink puts an ESP32 on your tailnet with its own `100.x.y.z` address, so other tailnet
devices can reach it (and it can reach them) over WireGuard, through NATs and cellular networks.

MicroLink is an independent implementation, written from the open-source Tailscale client.
It is not affiliated with or endorsed by Tailscale Inc.

**Status: beta.** It is used in the field on ESP32-S3 over WiFi and LTE, but it implements only
part of what the official client does. Read [Status and limitations](#status-and-limitations)
before you rely on it.

---

## What it does

- **Tailscale control protocol**: ts2021 Noise handshake, registration with an auth key,
  map updates over a long-poll stream (peers added, removed and patched by NodeID), key-expiry handling.
- **WireGuard** data plane on lwIP (based on [wireguard-lwip](https://github.com/smartalock/wireguard-lwip)),
  with Tailscale's 1280-byte tunnel MTU.
- **NAT traversal**: DISCO ping/pong/CallMeMaybe, STUN (IPv4 and IPv6, symmetric-NAT detection),
  and DERP relay fallback. Traffic uses DERP until DISCO proves a direct path, as in Tailscale.
- **Sockets over the tunnel**: a UDP API and an outbound TCP API that are bound to the VPN address.
- **4G/LTE** through SIMCom modems: PPP (real lwIP sockets, direct UDP possible) or an AT-command
  socket bridge, with optional WiFi ⇄ cellular failover and fast network rebinding.
- **Peer cache in NVS**, so known peers are usable right after a reboot.
- **Optional on-device web UI** for settings (password-protected, tailnet-only by default).

## Status and limitations

**Tested by the maintainer (Nov 2026, ESP32-S3 + 8 MB PSRAM, ESP-IDF 5.3):** registration, direct
WireGuard path, ICMP and UDP echo with a real Tailscale client against

| Control server | Transport | Result |
|---|---|---|
| Tailscale (hosted) | WiFi | direct path, 0% loss |
| Tailscale (hosted) | 4G PPP, SIM7600G-H + Soracom | direct path through carrier NAT, ~390 ms RTT, 0% loss |
| Headscale v0.29.7 (plain HTTP, Tailscale DERP map) | WiFi | direct path, 0% loss |
| Ionscale 0.18.0 (plain HTTP, Tailscale DERP map) | WiFi | direct path, 0% loss |

Also tested: repeated stop/start (no memory growth), reconnect after reboot.

**Tested by contributors:** ESP32-C3 without PSRAM (small tailnet, see PR #43); a Headscale-based
control plane over TLS (PR #22).

**Not supported (yet):**

- Tailscale **ACLs are not enforced on the device.** MicroLink does not parse the packet filter,
  so any peer that can see the device can reach any port it listens on. Restrict access with
  tailnet ACLs on the *other* devices, the config-UI allowlist, or your own checks.
- IPv4 tunnel addresses only (no `fd7a:…` IPv6 inside the tunnel).
- No subnet routes, exit nodes or `--advertise-routes` (issue #6).
- No interactive / QR-code login; an auth key is required (issue #8).
- No Tailscale SSH, Taildrop, MagicDNS server or HTTPS certificates.
  (`microlink_resolve()` looks a peer name up in the local peer list.)
- The DERP home region is set by hand (`CONFIG_ML_DERP_REGION`, default 9 = Dallas); there is
  no latency-based region selection.
- Peer table size is `CONFIG_ML_MAX_PEERS` (default 16, max 64). On a larger tailnet, extra peers
  are not tracked; use the priority peer or the allowlist to make sure the ones you need are.

The device shows up as **Linux** in the admin console (`Hostinfo.OS`).

## Requirements

- **ESP-IDF v5.3 or later**, including v6.x. CI builds every example with v5.3 and v5.5, and
  `basic_connect`/`cellular_connect` with v6.1. On IDF 6, cJSON comes from the component registry.
- An **ESP32-S3** is recommended (PSRAM strongly recommended). Classic ESP32 and ESP32-C3 build
  and have community reports, but are not part of the required CI checks.
- A Tailscale **auth key** (reusable keys survive re-registration; ephemeral keys do not).
- Optional: SIM7600-series or SIM7670-series modem for cellular.

## Quick start (WiFi)

```bash
git clone https://github.com/CamM2325/microlink.git
cd microlink/examples/basic_connect
idf.py set-target esp32s3
```

Set your credentials, either in `idf.py menuconfig` → **MicroLink V2 Configuration → Credentials**,
or in a git-ignored file:

```bash
cp sdkconfig.credentials.example sdkconfig.credentials
# edit WiFi SSID/password and CONFIG_ML_TAILSCALE_AUTH_KEY
```

`sdkconfig.credentials` is applied like `sdkconfig.defaults`: only when `sdkconfig` is created.
After editing it, delete `sdkconfig` (or run `idf.py fullclean`). Credentials end up **in the
firmware image**, so don't share built binaries.

If you are not in North America, set **MicroLink V2 Configuration → Preferred DERP region** to
your nearest region (region IDs are in the boot log and in `tailscale netcheck`).

```bash
idf.py build flash monitor
```

When the log shows `MicroLink state: CONNECTED`, find the device on your tailnet (default name
`esp32-xxyyzz` from the MAC address, or `CONFIG_ML_DEVICE_NAME`) and test it:

```bash
tailscale ping <device-name>
echo "hi" | nc -u -w1 <device-vpn-ip> 9000     # basic_connect replies "ECHO: hi"
```

## Examples

| Example | What it shows |
|---|---|
| `basic_connect` | WiFi, UDP echo on port 9000. Optional stop/start soak test (`ML_EXAMPLE_LIFECYCLE_CYCLES`). |
| `cellular_connect` | 4G only (PPP or AT bridge), UDP or TCP to a peer. |
| `cellular_heartbeat` | 4G heartbeat / dead-man pattern between two peers. |
| `failover_connect` | WiFi primary with cellular failover (`CONFIG_ML_ENABLE_NET_SWITCH`). |
| `rebind_test` | `microlink_rebind()` when switching networks. Reads WiFi credentials from NVS (written by the config UI). |

## Using MicroLink in your project

Add `components/microlink` and `components/microlink/components` (which holds `wireguard_lwip`)
to your project's `EXTRA_COMPONENT_DIRS`, as the examples do, then:

```c
#include "microlink.h"

static void on_state(microlink_t *ml, microlink_state_t state, void *ctx) {
    if (state == ML_STATE_AUTH_FAILED) { /* auth key rejected or expired */ }
}

void app_main(void) {
    /* ... bring up WiFi (or cellular, see below) first ... */
    microlink_config_t cfg = {
        .auth_key    = "tskey-auth-...",
        .device_name = "my-sensor",          /* NULL = esp32-<mac> */
    };
    microlink_t *ml = microlink_init(&cfg);   /* allocates state, loads keys; no tasks yet */
    microlink_set_state_callback(ml, on_state, NULL);
    microlink_start(ml);                      /* starts the internal tasks */

    while (!microlink_is_connected(ml)) vTaskDelay(pdMS_TO_TICKS(500));

    microlink_udp_socket_t *s = microlink_udp_create(ml, 9000);
    uint32_t peer = microlink_resolve(ml, "my-laptop");   /* lookup in the peer list */
    microlink_udp_send(s, peer, 9000, "hello", 5);
}
```

States: `IDLE → WIFI_WAIT → CONNECTING → REGISTERING → CONNECTED`, plus `RECONNECTING`,
`AUTH_FAILED` and `ERROR`. The state callback fires on `CONNECTED`, `RECONNECTING` and `AUTH_FAILED`.

### Lifecycle

- `microlink_stop()` asks the tasks to exit, unblocks their sockets and waits up to
  `CONFIG_ML_STOP_TIMEOUT_MS` (default 30 s). It returns `ESP_ERR_TIMEOUT` (and frees nothing) if a
  task is stuck in an uninterruptible call; call it again later. `microlink_start()` can then be
  called again on the same handle.
- Close your UDP/TCP sockets before stopping. Don't call stop/destroy from a MicroLink callback.
- `microlink_rebind()` moves an existing session to a new network interface without re-registering.
- `microlink_factory_reset()` erases the device keys, cached peers **and** all settings stored by the
  config UI (auth key, WiFi list, APN/PPP credentials, control host, UI password).

## API overview

The header [`microlink.h`](components/microlink/include/microlink.h) is the reference; this is a summary.

| Area | Functions |
|---|---|
| Lifecycle | `microlink_init`, `microlink_start`, `microlink_stop`, `microlink_destroy`, `microlink_rebind`, `microlink_factory_reset` |
| Status | `microlink_get_state`, `microlink_is_connected`, `microlink_get_vpn_ip`, `microlink_get_peer_count`, `microlink_get_peer_info` |
| Callbacks | `microlink_set_state_callback`, `microlink_set_peer_callback` |
| Names / IPs | `microlink_resolve`, `microlink_ip_to_str`, `microlink_parse_ip`, `microlink_default_device_name`, `microlink_imei_device_name` |
| UDP | `microlink_udp_create`, `microlink_udp_send`, `microlink_udp_recv`, `microlink_udp_set_rx_callback`, `microlink_udp_get_local_port`, `microlink_udp_close` |
| TCP (outbound) | `microlink_tcp_connect(ml, dest_ip, port, timeout_ms)`, `microlink_tcp_send`, `microlink_tcp_recv(sock, buf, len, timeout_ms)` → bytes or <0, `microlink_tcp_is_connected`, `microlink_tcp_close` |

Notes:

- IPs are `uint32_t` in host byte order (`microlink_parse_ip("100.64.0.5")`).
- UDP payloads are limited to 1400 bytes. Payloads above ~1250 bytes are fragmented inside the
  1280-byte tunnel; received datagrams above 1400 bytes are truncated.
- The UDP API is thread-safe. Each socket's RX callback runs on its own task
  (priority `CONFIG_ML_UDP_RX_TASK_PRIO`, default 7; use < 5 for heavy callbacks).
- Creating a UDP socket sends CallMeMaybe to known peers so they handshake with the device.
- Deprecated: `microlink_send()` returns `ESP_ERR_NOT_SUPPORTED` (it used to bypass WireGuard), and
  `microlink_set_data_callback()` is never called. `enable_derp`, `enable_stun` and `enable_disco`
  in `microlink_config_t` are ignored.

### Runtime configuration (`microlink_config_t`)

| Field | Meaning |
|---|---|
| `auth_key` | Required. |
| `device_name` | Hostname on the tailnet (default `esp32-<mac>`). |
| `max_peers` | Peer table size, 0 = `CONFIG_ML_MAX_PEERS`, clamped to it. |
| `priority_peer_ip` | Peer that may evict others when the table is full. |
| `disco_heartbeat_ms`, `stun_interval_ms`, `ctrl_watchdog_ms` | Defaults 3000 / 23000 / 120000. |
| `wifi_tx_power_dbm` | 0 = leave the driver default. |
| `ctrl_host`, `ctrl_noise_pubkey`, `streaming_map_fetch` | Custom control servers (see below). |

## Configuration (menuconfig)

All options are under **MicroLink V2 Configuration**. Values saved by the config UI in NVS
override the Kconfig defaults at runtime.

| Option | Default | Notes |
|---|---|---|
| `ML_MAX_PEERS` | 16 | Peers tracked (and WireGuard tunnels), 1–64. |
| `ML_DERP_REGION` | 9 | Home DERP region advertised to the control plane. |
| `ML_DERP_VERIFY_CERT` | y | Verify DERP TLS certificates against the ESP-IDF CA bundle. |
| `ML_PRIORITY_PEER_IP` | "" | Same as `priority_peer_ip`. |
| `ML_NVS_MAX_PEERS` | 64 | Peers cached in NVS (92 bytes each). |
| `ML_H2_BUFFER_SIZE_KB` / `ML_JSON_BUFFER_SIZE_KB` | 512 / 512 | Map-response buffers (PSRAM if present). Lower on boards without PSRAM. |
| `ML_ZERO_COPY_WG` | n | High-throughput receive path on a raw lwIP PCB (contributed by dj-oyu). |
| `ML_UDP_RX_TASK_PRIO` | 7 | UDP callback task priority. |
| `ML_STOP_TIMEOUT_MS` | 30000 | How long `microlink_stop()` waits. |
| MicroLink log verbosity | Same as ESP-IDF | Compile-time level for MicroLink's own logs (`ML_LOG_LEVEL_WARN` / `_INFO` / `_DEBUG` / `_VERBOSE`). Warning saves about 17–23 KB of flash. Debug/Verbose messages also need `esp_log_level_set("<tag>", ...)` at run time. |
| **Credentials** | | `ML_WIFI_SSID`, `ML_WIFI_PASSWORD`, `ML_TAILSCALE_AUTH_KEY`, `ML_DEVICE_NAME` (compiled into the image). |
| **Control Plane** | | `ML_CTRL_HOST`, `ML_CTRL_TLS`, `ML_CTRL_TLS_VERIFY_CERT` (y), `ML_CTRL_NOISE_PUBKEY_HEX`. |
| **Cellular Modem** | | `ML_ENABLE_CELLULAR`, board preset, pins, `ML_CELLULAR_APN`, `ML_CELLULAR_SIM_PIN`, `ML_CELLULAR_PPP_USER/PASS`, data mode, `ML_CELLULAR_FAST_BAUD` (0). |
| **Network Switching** | | `ML_ENABLE_NET_SWITCH`, `ML_NET_SWITCH_WIFI_TIMEOUT_MS` (30000), `ML_NET_SWITCH_HEALTH_INTERVAL_MS` (30000), `ML_NET_SWITCH_FAILBACK_MS` (120000, 0 = no failback): defaults for the `ml_net_switch_config_t` timing fields left at 0. |
| **HTTP Config Server** | | `ML_ENABLE_CONFIG_HTTPD` (n), `ML_CONFIG_HTTPD_PASSWORD`, `ML_CONFIG_HTTPD_ALLOW_LAN` (n), `ML_CONFIG_MAX_ALLOWED_PEERS`. |

APN, SIM PIN, PPP credentials and the control host are validated; invalid values are rejected at
startup (or with HTTP 400 in the config UI) instead of being passed to the modem.

## Cellular (4G/LTE)

Supported modules: SIMCom **SIM7600** series (tested: Waveshare SIM7600G-H) and **SIM7670** series
(board preset for LILYGO T-SIM7670G-S3; community-tested with A7670E).

**Wiring** (Waveshare SIM7600 preset, ESP32-S3): ESP **GPIO43 → modem RXD**, ESP **GPIO44 ← modem TXD**,
common **GND**. Power the modem from its own supply that can deliver ~2 A peaks; a PC USB port or the
ESP's 3V3 pin is not enough and causes registration failures. Attach the main LTE antenna.

**Data modes** (`Cellular data mode`):

- **Auto** (default): PPP first, AT socket bridge if PPP fails.
- **PPP only**: lwIP gets a real network interface; direct peer-to-peer UDP is possible.
- **AT socket only**: uses the modem's own TCP/IP stack; all VPN traffic is relayed through DERP.
  The UART stays in command mode, so your application can send its own AT commands with
  `ml_cellular_send_at_cmd()` (single `AT+…` commands; commands that would break the bridge, such as
  `+CIP*`, `+NET*`, `+CFUN` and `+IPR`, are refused).

The UART runs at 115200 baud unless you set `ML_CELLULAR_FAST_BAUD` (e.g. 921600 with short wiring
or flow control). If the modem was left at another rate, the driver detects it and resets it.

For cellular-only apps, call `ml_cellular_init()` and `ml_cellular_connect()` before `microlink_init()`
(see `examples/cellular_connect`).

| Measured (SIM7600G-H, 115200 baud, ~16–20-peer tailnet) | PPP | AT bridge |
|---|---|---|
| UDP / ICMP round trip | 350–430 ms direct (Soracom, Nov 2026); 300–600 ms (EIOT, Mar 2026) | 3–15 s via DERP (Mar 2026) |
| Boot → connected | 38 s (Soracom, Nov 2026); ~35–50 s (EIOT, Mar 2026) | ~60–90 s (Mar 2026) |
| Throughput | ~6.5 KB/s (Mar 2026) | ~0.45 KB/s (Mar 2026) |

| Carrier | APN | Auth | Status |
|---|---|---|---|
| EIOT / BICS | `america.bics` | PAP, empty credentials | Tested |
| Soracom | `soracom.io` | CHAP `sora`/`sora` | Tested (Nov 2026, T-Mobile) |

PPP uses CHAP when credentials are set, otherwise PAP with empty credentials.

### WiFi ⇄ cellular failover

With `CONFIG_ML_ENABLE_NET_SWITCH`, `ml_net_switch_init()`/`ml_net_switch_start()` (see
[`ml_net_switch.h`](components/microlink/include/ml_net_switch.h)) run WiFi as primary and cellular as
backup, rebinding the VPN session when the network changes and falling back to a full restart if
needed. If both fail, it keeps retrying with backoff. Don't cache the handle from
`ml_net_switch_get_handle()`; it changes when the VPN is restarted.

## Custom control servers (Headscale, Ionscale)

MicroLink talks to `controlplane.tailscale.com` by default. Headscale and Ionscale are tested (see
[Status](#status-and-limitations)). You need **both** the host and the server's Noise public key;
the key is not fetched automatically. The control connection uses port 80 (or 443 with TLS).

```
CONFIG_ML_CTRL_HOST="headscale.example.com"
CONFIG_ML_CTRL_NOISE_PUBKEY_HEX="<64 hex chars from https://<host>/key?v=131, without the mkey: prefix>"
CONFIG_ML_CTRL_TLS=y          # if the server only listens on HTTPS (443)
```

(or set `ctrl_host` / `ctrl_noise_pubkey` in `microlink_config_t`; the config UI can set only the host).
Headscale doesn't answer the initial `Stream=false` map request; MicroLink detects this and switches
to a streaming fetch automatically (or set `CONFIG_ML_CTRL_STREAMING_MAP_FETCH` /
`streaming_map_fetch = true` to start that way). Erase NVS (`idf.py erase-flash`, or
`parttool.py erase_partition --partition-name=nvs`) when moving a board between control servers. If your DERP or HTTPS
endpoint uses a private CA, add it to the certificate bundle (`CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE`)
or turn off `ML_DERP_VERIFY_CERT` / `ML_CTRL_TLS_VERIFY_CERT`.

## Config web UI

Enable `CONFIG_ML_ENABLE_CONFIG_HTTPD` (off in all examples). The UI at `http://<vpn-ip>/` shows status
and lets you change the auth key, WiFi list, cellular settings, control host and a peer allowlist.

- **Login**: HTTP Basic auth, user `admin`. Set `ML_CONFIG_HTTPD_PASSWORD`, or leave it empty and a
  random password is generated on first boot, stored in NVS and printed once on the serial console.
- **Reachable only on the tailnet address** unless `ML_CONFIG_HTTPD_ALLOW_LAN=y` (then the password
  crosses the LAN unencrypted). Never on the cellular carrier address.
- The **allowlist** is an access filter: peers not on it get no WireGuard tunnel to the device.

## Security

- Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).
- DERP (and optional control-plane) TLS certificates are verified by default.
- Keys, auth key and config-UI settings are stored in NVS **unencrypted**, and Kconfig credentials are
  compiled into the image. For deployed devices enable ESP-IDF flash encryption + NVS encryption, and
  use tagged, pre-approved auth keys.
- MicroLink falls back to Google's public STUN server if Tailscale's STUN servers are unreachable.
- See [Status and limitations](#status-and-limitations) for the ACL caveat.

## Memory

On ESP32-S3 with PSRAM, MicroLink's own code and strings take roughly 105–130 KB of flash
(`basic_connect` / `cellular_connect`, ESP-IDF 5.3, `-Os`, measured Nov 2026 from the linker map),
or 85–105 KB with `CONFIG_ML_LOG_LEVEL_WARN`. The four internal tasks use 42 KB of
stack (8 + 14 + 12 + 8 KB), plus 4 KB per UDP socket. Map-response buffers are allocated while
fetching and use PSRAM when available.

Without PSRAM, reduce `ML_H2_BUFFER_SIZE_KB`/`ML_JSON_BUFFER_SIZE_KB` and `ML_MAX_PEERS`. One
measurement (ESP32-C3, PR #43) saw about 3 KB of map data per peer, so 64 KB buffers fit roughly
20 peers. Exact limits depend on your tailnet.

### Smaller images

The examples build with `-Os`; the WireGuard/DISCO crypto is still compiled with `-O2`.
`examples/sdkconfig.size.defaults` is an optional overlay that trims ESP-IDF further:

```bash
cd examples/basic_connect
rm -f sdkconfig   # defaults only apply when sdkconfig is created
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;../sdkconfig.size.defaults" build
```

| Image size in bytes (esp32s3) | `basic_connect` | `cellular_connect` |
|---|---:|---:|
| ESP-IDF 5.3, example defaults | 995,996 | 782,904 |
| ESP-IDF 5.3, + `sdkconfig.size.defaults` | 769,012 | 598,840 |
| ESP-IDF 5.3, + `CONFIG_ML_LOG_LEVEL_WARN=y` as well | 753,320 | 577,920 |
| ESP-IDF 6.1.1, example defaults | 991,915 | 721,771 |
| ESP-IDF 6.1.1, + `sdkconfig.size.defaults` | 855,635 | 639,463 |

The overlay uses the common CA bundle instead of the full one (Let's Encrypt, used by Tailscale, is
included; a headscale or DERP server with a certificate from a less common CA needs the full
bundle), newlib-nano printf (no 64-bit or float formats in your own logs), a client-only mbedTLS
with fewer curves and ciphers, WiFi without Enterprise/SoftAP/OWE, and no `esp_err_to_name()`
strings or log colours. The file lists each option; check them against your deployment.

## Troubleshooting

| Symptom | Check |
|---|---|
| `AUTH_FAILED` state / registration refused | Auth key expired or single-use; the log shows the server's error. |
| `Control plane health: …` warnings | Messages from the control server, e.g. an expired node key. Re-authorise the device or use a new key. |
| Connected but unreachable, high latency | Wrong DERP region: set `CONFIG_ML_DERP_REGION`. Symmetric NAT (logged at boot) prevents direct paths. |
| Peers missing | Peer table full (`Peer table full` in the log): raise `ML_MAX_PEERS` or set a priority peer. |
| `TLS handshake failed` / certificate not accepted | Private CA on a self-hosted DERP/HTTPS server (see Custom control servers). |
| Map response truncated or out of memory | Raise the H2/JSON buffer sizes or enable PSRAM. |
| Cellular `SIM not detected` / no reply to AT | Wiring (TX/RX crossed), modem power supply, baud rate. |
| Cellular `PPP CHAP authentication failed` | Wrong PPP credentials or APN; try empty credentials (PAP). |
| App too large for partition | Use a larger app partition (examples use `PARTITION_TABLE_SINGLE_APP_LARGE`). |

## Development

```bash
# Host unit tests (no hardware): WireGuard filters, Noise AEAD, AT parameter validation
cmake -S test/host -B build-host -DLWIP_INCLUDE_DIR=$IDF_PATH/components/lwip/lwip/src/include
cmake --build build-host && ctest --test-dir build-host --output-on-failure
```

CI (GitHub Actions) runs the host tests with ASan/UBSan, builds the examples across ESP-IDF versions,
and runs CodeQL and OpenSSF Scorecard. Contributions are welcome; please include how you tested
(board, transport, control server).

More: [TESTING_GUIDE.md](TESTING_GUIDE.md) · [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
[docs/LARGE_TAILNET.md](docs/LARGE_TAILNET.md) · [docs/TAILSCALE_REFERENCE.md](docs/TAILSCALE_REFERENCE.md)
(design notes from the Tailscale client).

## Acknowledgments

Developed by **[Malone Technologies LLC](https://github.com/Malone-Technologies)**.
Development was supported in part by **[Polymath Robotics](https://www.polymathrobotics.com/)**.

**Built on:** the open-source [Tailscale](https://github.com/tailscale/tailscale) client (protocol
reference), [WireGuard](https://www.wireguard.com/), [wireguard-lwip](https://github.com/smartalock/wireguard-lwip),
[lwIP](https://savannah.nongnu.org/projects/lwip/), and [Headscale](https://github.com/juanfont/headscale).

**Contributors:**

- [@kentaro](https://github.com/kentaro) (Kentaro Kuribayashi): custom control planes over TLS, streaming map fetch, auth-failure state (#22)
- [@antonmeyer](https://github.com/antonmeyer): lwIP thread-safety fixes, DERP region option, handshake retry cap, DISCO and online-status fixes (#28, #29, #39, #40)
- [@kedimuzafer](https://github.com/kedimuzafer): datapath logging, DISCO key cache, RX drop fix, zero-copy WireGuard output (#30–#33)
- [@snowpaper](https://github.com/snowpaper): DERP until DISCO validates a direct path (#21)
- [@letalvoj](https://github.com/letalvoj) (Vojtěch Létal): peer online status (#24)
- [@ViniciusDev26](https://github.com/ViniciusDev26) (Carlos Vinicius): small-buffer underflow and corruption fixes (#35)
- [@Asimmimx](https://github.com/Asimmimx) (Asım Mirza Çiftler): ESP32-C3 / no-PSRAM support (#43)
- [@dj-oyu](https://github.com/dj-oyu): zero-copy WireGuard receive mode
- [@GrieferPig](https://github.com/GrieferPig): early WireGuard peer-lookup fix (since replaced by longest-prefix routing)

Fixes were also adapted from community forks (credited in the commit messages), including
Csontikka, TailTiny (Asimmimx), antmanler, fugo101, MedAouadhi and TimelyToga.

**Security reports:** Tomasz Fiedoruk and Adrian Nguyen ([fugo101](https://github.com/fugo101)).

## License

MIT, see [LICENSE](LICENSE). Bundled third-party code keeps its own license:
`wireguard_lwip` (BSD-3-Clause, Daniel Hope / Smartalock) and X25519 (see `x25519-license.txt`).
