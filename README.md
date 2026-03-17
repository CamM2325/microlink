# MicroLink v2 — ESP32 Tailscale Client

Production-ready Tailscale VPN client for the ESP32 platform with WiFi and 4G cellular support. Should work on most ESP32 variants (ESP32, ESP32-S3, ESP32-P4, etc.) — ESP32-S3 with PSRAM recommended for production.

## Features

- **Full Tailscale Protocol Support**
  - ts2021 coordination protocol
  - WireGuard encryption (ChaCha20-Poly1305)
  - DISCO path discovery (PING/PONG/CALL_ME_MAYBE)
  - DERP relay with dynamic region discovery (up to 32 regions)
  - STUN for public IP / NAT type discovery (IPv4 + IPv6)
  - Delta updates (PeersChanged, PeersRemoved, PeersChangedPatch)
  - MagicDNS hostname resolution (short name or FQDN)
  - Key expiry detection and auto re-registration

- **WiFi + 4G Cellular**
  - WiFi primary with automatic cellular failback
  - PPP cellular data — real lwIP sockets, direct UDP, NAT hole-punching
  - AT socket bridge fallback for carriers that reject PPP auth
  - Multi-carrier: PAP (IMSI-based) and CHAP (credential-based) automatic selection
  - Seamless network rebind — switch between WiFi and cellular without destroying the VPN session (~330ms rebind, ~7s recovery)
  - Network health monitoring with automatic failback to WiFi when recovered

- **Production Ready**
  - Fully async, task-based architecture (no polling loop)
  - Tested with 300+ peer tailnets (PSRAM-backed 512KB buffers)
  - NVS peer cache — DISCO probing starts immediately on reboot
  - Proactive H2 WINDOW_UPDATE for fast MapResponse downloads
  - Key expiry handling with reusable auth keys

- **Broad Hardware Support**
  - Tested on ESP32-S3, ESP32-WROOM-32D, and HiLetgo ESP-32S
  - Should work on most ESP32 variants with WiFi and sufficient RAM
  - Memory-optimized: ~85-116KB SRAM static, PSRAM for large tailnet buffers

- **HTTP Config Server**
  - Web UI at `http://<vpn-ip>/` — system monitor, peer management, device settings
  - REST API: `/api/settings`, `/api/peers`, `/api/peers/allowed`, `/api/monitor`, `/api/status`, `/api/restart`
  - All settings persist in NVS — no rebuild needed
  - Ifdef-gated: zero cost when disabled

- **Advanced Features**
  - Zero-copy WireGuard receive (raw lwIP PCB, for 30fps+ video streaming)
  - DISCO peer filtering / allowlist (reduces jitter on large tailnets)
  - Priority peer (guaranteed WG slot even when peer table is full)
  - Headscale / Ionscale compatible (configurable control plane host)
  - Credential security: all secrets in git-ignored sdkconfig

## Requirements

- ESP-IDF v5.0 or later (tested with v5.3)
- ESP32 with WiFi (ESP32-S3 with PSRAM recommended)
- Tailscale account with auth key (generate at https://login.tailscale.com/admin/settings/keys)
- For cellular: ESP32-compatible 4G cellular module (e.g., SIM7600, SIM7670) + active SIM card

## Hardware

### Tested Boards

| Board | Type | Notes |
|-------|------|-------|
| ESP32-S3 with 8MB PSRAM | WiFi | Recommended for production |
| Seeed Studio XIAO ESP32S3 | WiFi + Cellular | Pairs with Waveshare SIM7600X |
| Waveshare ESP32-S3-Touch-AMOLED-2.06 | WiFi | Touchscreen display |
| HiLetgo ESP-32S | WiFi | Budget option, no PSRAM |
| ESP32-WROOM-32D / DevKitC | WiFi | Standard dev board, no PSRAM |

### Tested Cellular Modules

| Module | Interface | Notes |
|--------|-----------|-------|
| Waveshare SIM7600G-H 4G | UART | PPP + AT socket bridge, tested with EIOT and Soracom SIMs |
| LILYGO T-SIM7670G-S3 | UART | Integrated ESP32-S3 + SIM7670G |

### Should Work (Untested)

MicroLink uses standard ESP-IDF APIs — any ESP32 variant with WiFi and sufficient RAM should work. ESP32-P4, ESP32-C3, ESP32-C6, etc. Boards with PSRAM are recommended for large tailnets (100+ peers).

## Quick Start

### 1. Clone and enter an example

```bash
git clone https://github.com/CamM2325/microlink.git
cd microlink/examples/basic_connect    # or: cellular_connect, cellular_heartbeat, failover_connect
```

### 2. Configure sdkconfig

Add these settings to your `sdkconfig.defaults` file:

```ini
# PSRAM Configuration (required for ESP32-S3 with PSRAM)
CONFIG_SPIRAM=y
CONFIG_SPIRAM_MODE_OCT=y
CONFIG_SPIRAM_TYPE_AUTO=y
CONFIG_SPIRAM_SPEED_80M=y
CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY=y
CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=4096
CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=32768

# Partition table (app needs ~1MB+)
CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y

# TLS/HTTPS (required for DERP and control plane)
CONFIG_ESP_TLS_USING_MBEDTLS=y
CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_CMN=y

# Networking
CONFIG_LWIP_IPV4=y
CONFIG_LWIP_IP4_FRAG=y
CONFIG_LWIP_IP4_REASSEMBLY=y

# Stack size
CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192
```

### 3. Configure credentials

```bash
cp sdkconfig.credentials.example sdkconfig.credentials
# Edit sdkconfig.credentials with your WiFi SSID/password, Tailscale auth key, etc.
```

Or run `idf.py menuconfig` → MicroLink V2 → Credentials to set them interactively.

Credentials are stored in `sdkconfig` (which is gitignored) so they are never accidentally committed to version control.

### 4. Build and flash

```bash
source ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

### 5. Test

From any device on your tailnet:

```bash
tailscale ping esp32-microlink
```

You should see:

```
pong from esp32-microlink (100.x.x.x) via DERP(dfw) in 150ms
```

## Memory Footprint

### Static Memory (measured with `idf.py size`, ESP-IDF v5.3, ESP32-S3)

| Build | SRAM (static) | Flash | IRAM | Free SRAM |
|-------|---------------|-------|------|-----------|
| WiFi + Web UI (`basic_connect`) | 116 KB | 950 KB | 16 KB | 226 KB |
| WiFi + Cellular failover (`failover_connect`) | 123 KB | 950 KB | 16 KB | 219 KB |
| Cellular only (`cellular_connect`) | 85 KB | 758 KB | 16 KB | 256 KB |

### Runtime Memory (allocated from heap at startup)

| Resource | Size | Location |
|----------|------|----------|
| Task stacks (coord + derp_tx + net_io + wg_mgr) | 42 KB | SRAM |
| H2 receive buffer | 512 KB (configurable) | PSRAM |
| JSON parse buffer | 512 KB (configurable) | PSRAM |
| NVS peer cache (64 peers) | ~6 KB | PSRAM |
| HTTP config server | ~7 KB | SRAM (ifdef-gated) |
| Per WG peer | ~200 bytes | SRAM |

### ESP32-S3 with PSRAM (Recommended)

MapResponse buffers (H2 + JSON) are allocated from PSRAM only during coordination polling, then freed. Peak PSRAM usage is ~1MB (~12% of 8MB). Leaves 200KB+ SRAM free for your application.

### ESP32 without PSRAM

Boards without PSRAM can reduce H2/JSON buffers to 64KB via menuconfig (sufficient for ~30 peers). Total SRAM usage: ~140KB. Suitable for simple sensor reporting, heartbeats, and small data payloads. Not recommended for large tailnets or memory-heavy applications.

```ini
# sdkconfig.defaults for ESP32 without PSRAM
CONFIG_ML_H2_BUFFER_SIZE_KB=64
CONFIG_ML_JSON_BUFFER_SIZE_KB=64
CONFIG_ML_MAX_PEERS=8
```

## Examples

| Example | Description | Hardware |
|---------|-------------|----------|
| `basic_connect` | WiFi → Tailscale → UDP echo + web config | Any ESP32 with WiFi |
| `cellular_connect` | 4G cellular → Tailscale → bidirectional UDP | XIAO + Waveshare SIM7600 |
| `cellular_heartbeat` | Periodic heartbeat over 4G cellular | XIAO + Waveshare SIM7600 |
| `failover_connect` | WiFi primary + cellular fallback | XIAO + Waveshare SIM7600 |

## Architecture

MicroLink v2 uses a fully async, task-based architecture. All protocol operations run concurrently in dedicated FreeRTOS tasks with queue-based IPC — no polling loop needed.

```
┌─────────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐
│ coord_task  │  │ derp_tx  │  │ net_io   │  │ wg_mgr  │
│ (Tailscale  │  │ (DERP    │  │ (select  │  │ (WG +   │
│  control)   │  │  relay)  │  │  loop)   │  │  DISCO) │
└──────┬──────┘  └────┬─────┘  └────┬─────┘  └────┬────┘
       │              │             │              │
       └──────────────┴─────────────┴──────────────┘
                          │
                    Queue-based IPC
                          │
                ┌─────────┴─────────┐
                │   WiFi / Cellular  │
                │  (ml_net_switch)   │
                └───────────────────┘
```

**Key differences from v1:**
- No `microlink_update()` polling — all tasks run independently
- Queue-based IPC instead of shared state + mutexes (no deadlocks)
- Dedicated DERP TX task (non-blocking sends)
- `select()` loop in net_io for multiplexed packet routing

### Task Stack Sizes

| Task | Stack | Purpose |
|------|-------|---------|
| `coord_task` | 12 KB | Tailscale control plane (TLS, H2, JSON parsing) |
| `derp_tx` | 14 KB | DERP relay send (TLS overhead) |
| `net_io` | 8 KB | UDP packet routing (select loop) |
| `wg_mgr` | 8 KB | WireGuard + DISCO + STUN |

## API Reference

### Initialization

```c
// Get a default configuration
microlink_config_t config = {
    .auth_key = "tskey-auth-...",
    .device_name = "my-sensor",
    .enable_derp = true,
    .enable_disco = true,
    .enable_stun = true,
    .max_peers = 16,
};

// Initialize (creates tasks, does NOT connect yet)
microlink_t *ml = microlink_init(&config);

// Start connecting (WiFi must be up)
microlink_start(ml);
```

### Connection Status

```c
// Check connection state
microlink_state_t state = microlink_get_state(ml);
bool connected = microlink_is_connected(ml);

// Get our VPN IP
uint32_t vpn_ip = microlink_get_vpn_ip(ml);
char ip_str[16];
microlink_ip_to_str(vpn_ip, ip_str);
// ip_str = "100.x.y.z"
```

Connection states: `ML_STATE_IDLE` → `ML_STATE_WIFI_WAIT` → `ML_STATE_CONNECTING` → `ML_STATE_REGISTERING` → `ML_STATE_CONNECTED`

### UDP Communication

```c
// Create UDP socket bound to VPN IP
microlink_udp_socket_t *sock = microlink_udp_create(ml, 9000);

// Send to a peer
uint32_t dest = microlink_parse_ip("100.x.y.z");
microlink_udp_send(sock, dest, 9000, data, len);

// Blocking receive with timeout
uint32_t src_ip;
uint16_t src_port;
size_t recv_len = sizeof(buffer);
esp_err_t err = microlink_udp_recv(sock, &src_ip, &src_port, buffer, &recv_len, 5000);

// Or use a callback for immediate handling
microlink_udp_set_rx_callback(sock, my_rx_handler, user_data);

// Cleanup
microlink_udp_close(sock);
```

### TCP Communication

```c
// Connect to a peer over the WG tunnel (triggers handshake if needed)
microlink_tcp_socket_t *sock = microlink_tcp_connect(ml, "100.x.y.z", 5055);

// Send data
microlink_tcp_send(sock, data, len);

// Blocking receive with timeout (milliseconds)
size_t recv_len = sizeof(buffer);
esp_err_t err = microlink_tcp_recv(sock, buffer, &recv_len, 5000);

// Check connection status
bool up = microlink_tcp_is_connected(sock);

// Cleanup
microlink_tcp_close(sock);
```

TCP sockets are routed through the WireGuard tunnel by binding to the VPN IP internally. The connect call will wait up to 30 seconds for the WG handshake to complete if the peer tunnel isn't already up.

### MagicDNS Resolution

```c
// Resolve short name or FQDN to VPN IP (local lookup, no network call)
uint32_t ip = microlink_resolve(ml, "npc1");           // short name
uint32_t ip = microlink_resolve(ml, "npc1.tail1234.ts.net");  // FQDN
```

### Peer Information

```c
int count = microlink_get_peer_count(ml);
for (int i = 0; i < count; i++) {
    microlink_peer_info_t info;
    microlink_get_peer_info(ml, i, &info);
    char ip[16];
    microlink_ip_to_str(info.vpn_ip, ip);
    printf("Peer: %s (%s) %s\n", info.hostname, ip,
           info.direct_path ? "direct" : "via DERP");
}
```

### Callbacks

```c
// State change notification
microlink_set_state_callback(ml, on_state_change, user_data);

// Peer discovered/updated
microlink_set_peer_callback(ml, on_peer_update, user_data);

// Raw data received (alternative to UDP socket API)
microlink_set_data_callback(ml, on_data, user_data);
```

### Network Switching (WiFi + Cellular Failover)

```c
// Instead of microlink_init() directly, use the net_switch module:
ml_net_switch_config_t ns_config = {
    .wifi_ssid = "MyWiFi",
    .wifi_pass = "MyPassword",
    .cell_tx_pin = 43,
    .cell_rx_pin = 44,
};
ml_net_switch_init(&ns_config);
ml_net_switch_start();

// Get the MicroLink handle (same API as above)
microlink_t *ml = ml_net_switch_get_handle();
```

### Network Rebind

```c
// Switch the VPN to a new network interface without destroying the session.
// Preserves WG peer state, crypto keys, VPN IP, and DISCO state.
// Closes/recreates DISCO+STUN sockets, signals coord+DERP to reconnect.
// ~330ms rebind, ~7s VPN recovery.
esp_err_t ret = microlink_rebind(ml);
```

The `ml_net_switch` module calls `microlink_rebind()` automatically during WiFi↔cellular transitions.

### Cleanup

```c
microlink_stop(ml);
microlink_destroy(ml);
```

### Factory Reset

```c
// Erase all stored keys and cached peers (call BEFORE init)
microlink_factory_reset();
```

## Bidirectional UDP Communication

MicroLink supports full bidirectional UDP communication over the Tailscale VPN. The ESP32 can both send and receive without waiting for a peer to initiate.

### How It Works

1. **Magicsock Mode**: WireGuard and DISCO share a single UDP socket — no port conflicts
2. **Direct Path Discovery**: DISCO protocol finds the optimal path (direct UDP or DERP relay)
3. **Cryptokey Routing**: Packets are routed based on peer's VPN IP using /32 allowed IPs
4. **CallMeMaybe**: On UDP socket creation, triggers WG handshakes to all known peers

### Example: Echo Server

```bash
# On PC — send to ESP32, receive echo
echo "hello" | nc -u 100.x.y.z 9000

# On PC — listen for ESP32-initiated messages
nc -u -l 9000
```

### Timing

| Event | WiFi | Cellular (PPP) | Cellular (AT socket) |
|-------|------|-----------------|----------------------|
| Boot → connected | ~15-20s | ~35-50s | ~60-90s |
| Handshake | 1-5s | 1-5s | 3-10s |
| Round-trip (DERP) | 30-150ms | 300-600ms | 3-15s |
| Round-trip (direct) | 5-50ms | 265-390ms | N/A |

## Cellular Performance

MicroLink uses PPP for cellular data, giving real lwIP sockets instead of routing through AT commands. This enables direct UDP, STUN, and NAT hole-punching — eliminating the DERP relay hop for peers on non-symmetric NATs.

### PPP vs AT Socket Bridge

| Metric | PPP (direct UDP) | AT Socket Bridge (DERP) |
|--------|-------------------|-------------------------|
| UDP round-trip | 300-600ms | 3-15s |
| ICMP ping | 400-700ms | 5-15s |
| Boot → connected | ~35-50s | ~60-90s |
| MapResponse (24KB) | ~8s | ~64s |
| Throughput @ 115200 | 6.5 KB/s | ~0.45 KB/s |
| Transport | Direct peer-to-peer UDP | DERP relay only |

*Measured on a ~20 peer tailnet. Boot and MapResponse times increase with tailnet size — a 300+ peer tailnet will take significantly longer for the initial MapResponse download.*

### PPP Data Path

When PPP is active, the modem UART carries raw IP packets via the PPP protocol. lwIP creates a `ppp_netif` network interface, and all standard BSD socket calls (connect, send, recv) work directly — no AT command overhead. This is the same mechanism your phone uses for cellular data.

### AT Socket Bridge Fallback

If PPP authentication fails (e.g., carrier rejects CHAP/PAP), MicroLink automatically falls back to the AT socket bridge. This uses the modem's internal TCP/IP stack via AT commands (`AT+CIPOPEN`, `AT+CIPSEND`, etc.). It's slower but works with any carrier.

### Carrier Compatibility

PPP authentication is automatic — CHAP with credentials when provided, PAP with empty credentials for IMSI-based carriers. Falls back to AT socket bridge if PPP fails.

| Carrier | APN | Auth | Status |
|---------|-----|------|--------|
| EIOT/BICS | `america.bics` | PAP (empty creds) | Tested |
| Soracom | `soracom.io` | CHAP (`sora`/`sora`) | Tested |
| Google Fi | `h2g2` | PAP (empty creds) | Untested |
| TEAL | `teal` | PAP (empty creds) | Untested |

### Bandwidth Contention

During large downloads (MapResponse parsing, delta updates), DISCO/STUN/WG probes continue with elevated RTTs (800-1800ms vs 500ms normal). Once the download completes, latency returns to normal. All protocol tasks run concurrently without blocking each other.

## HTTP Config Server

Enable `CONFIG_ML_ENABLE_CONFIG_HTTPD=y` in sdkconfig.defaults to get a web UI accessible at `http://<vpn-ip>/` from any device on your tailnet.

**System Monitor** — Real-time ESP32 temperature, WiFi RSSI (or cellular indicator), uptime, heap/PSRAM usage, DERP region, peer count, per-task stack watermarks. Auto-refreshes every 3 seconds.

**Peer Allowlist** — Manage which peers receive DISCO probes. Changes take effect immediately (no restart). On large tailnets (200+ devices), this limits DISCO probing to only the peers that matter.

**All Tailnet Peers** — Paginated peer list (25 per page) with search/filter, direct/DERP path status, and one-click "Allow" buttons. Peers not in the allowlist show a "Not Allowed" badge when filtering is active.

**Device Settings** — WiFi, Tailscale auth key, device name, cellular APN, plus advanced settings (max peers, DISCO heartbeat, priority peer, control plane host for Headscale/Ionscale, debug flags). All persist in NVS and take effect on restart.

**Resource usage** — ~28KB flash, ~7KB RAM (6KB HTTP task stack + 1KB NVS config). Ifdef-gated: zero cost when disabled (`CONFIG_ML_ENABLE_CONFIG_HTTPD=n`).

**REST API** — All functionality available via JSON endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/settings` | GET/POST | Read/write device settings |
| `/api/peers` | GET | List all tailnet peers |
| `/api/peers/allowed` | GET/POST | Manage DISCO probe allowlist |
| `/api/monitor` | GET | System health (temp, heap, RSSI, uptime) |
| `/api/status` | GET | Connection state and VPN IP |
| `/api/restart` | POST | Restart the device |

**Device naming** — Set a prefix (e.g. `sensor`) to auto-generate `sensor-a1b2c3` from MAC, or set a full custom name. Tailscale creates the DNS entry: `your-name.your-tailnet.ts.net`.

## Configuration

All settings via `idf.py menuconfig` → MicroLink V2 Configuration.

### Runtime Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `auth_key` | Required | Tailscale auth key (reusable + ephemeral recommended) |
| `device_name` | Auto-generated | Device hostname (`esp32-XXYYZZ` from MAC, or `prefix-IMEI` for cellular) |
| `enable_derp` | `true` | Enable DERP relay |
| `enable_disco` | `true` | Enable DISCO path discovery |
| `enable_stun` | `true` | Enable STUN NAT discovery |
| `max_peers` | `16` | Maximum simultaneous active WireGuard tunnels (tailnet can have 300+ peers) |
| `priority_peer_ip` | `0` | VPN IP of priority peer (guaranteed WG slot) |
| `disco_heartbeat_ms` | `3000` | DISCO keepalive interval |
| `stun_interval_ms` | `23000` | STUN re-probe interval |
| `ctrl_watchdog_ms` | `120000` | Control plane watchdog timeout |
| `wifi_tx_power_dbm` | `0` (default) | WiFi TX power in dBm |

### Kconfig Options (`idf.py menuconfig`)

```
MicroLink V2 Configuration
├── Core
│   ├── Enable zero-copy WireGuard receive    [ ]
│   ├── Maximum simultaneous WireGuard peers  (16)
│   ├── Maximum cached peers in NVS           (64)
│   ├── Priority peer VPN IP                  ()
│   ├── HTTP/2 receive buffer size (KB)       (512)
│   └── JSON parse buffer size (KB)           (512)
├── Credentials
│   ├── WiFi SSID                             ()
│   ├── WiFi Password                         ()
│   ├── Tailscale Auth Key                    ()
│   └── Device Name                           ()
├── Cellular Modem
│   ├── Enable cellular modem support         [ ]
│   ├── Cellular board type                   (Waveshare SIM7600X)
│   ├── Cellular UART TX GPIO pin             (43)
│   ├── Cellular UART RX GPIO pin             (44)
│   ├── Modem PWRKEY GPIO pin                 (-1)
│   ├── Modem DTR GPIO pin                    (-1)
│   ├── Cellular APN                          ()
│   ├── SIM Card PIN                          ()
│   ├── PPP CHAP username                     ()
│   └── PPP CHAP password                     ()
├── Network Switching
│   ├── Enable WiFi/Cellular network switching [ ]
│   ├── WiFi connect timeout (ms)             (30000)
│   ├── Health check interval (ms)            (30000)
│   └── WiFi failback check interval (ms)     (120000)
└── HTTP Config Server
    ├── Enable HTTP configuration server       [ ]
    └── Maximum peers in allowlist             (16)
```

#### Core Options

| Option | Default | Description |
|--------|---------|-------------|
| `ML_ZERO_COPY_WG` | `n` | Zero-copy WireGuard via raw lwIP PCB (for 30fps+ streaming). See [High-Throughput Mode](#high-throughput-mode-zero-copy-wireguard). |
| `ML_MAX_PEERS` | `16` | Maximum simultaneous active WireGuard tunnels (1-64). Each uses ~200 bytes. This is NOT the tailnet size limit — MicroLink tracks all peers (300+) but only maintains active tunnels to this many at once. Reduce to 8 for non-PSRAM. |
| `ML_NVS_MAX_PEERS` | `64` | Peers cached in NVS flash (16-1024). Persists across reboots so DISCO probing starts immediately. Each entry: 92 bytes. LRU eviction when full. |
| `ML_PRIORITY_PEER_IP` | Empty | Priority peer VPN IP (e.g., `100.x.y.z`). Guaranteed a WG slot even when peer table is full — LRU non-priority peer is evicted. Also settable via web UI. |
| `ML_H2_BUFFER_SIZE_KB` | `512` | H2 receive buffer (64-2048 KB, PSRAM-backed). Size determines max tailnet: 64KB ≈ 30 peers, 512KB ≈ 300 peers, 2048KB ≈ 1200 peers. |
| `ML_JSON_BUFFER_SIZE_KB` | `512` | JSON parse buffer (64-2048 KB, PSRAM-backed). cJSON DOM uses 2-3x raw JSON size. Match to H2 buffer. |

#### Credentials

| Option | Default | Description |
|--------|---------|-------------|
| `ML_WIFI_SSID` | Empty | WiFi network SSID |
| `ML_WIFI_PASSWORD` | Empty | WiFi network password |
| `ML_TAILSCALE_AUTH_KEY` | Empty | Tailscale auth key from https://login.tailscale.com/admin/settings/keys |
| `ML_DEVICE_NAME` | Empty | Custom hostname. Empty = auto-generate from MAC (`esp32-a1b2c3`) or IMEI (`prefix-IMEI`). |

#### Cellular Modem

| Option | Default | Description |
|--------|---------|-------------|
| `ML_ENABLE_CELLULAR` | `n` | Enable 4G cellular modem support (ESP32-compatible modules via UART AT commands + PPP) |
| `ML_CELLULAR_BOARD` | Waveshare | Board preset: Waveshare SIM7600X (TX=43,RX=44), LILYGO T-SIM7670G (TX=11,RX=10,PWRKEY=18), or Custom |
| `ML_CELLULAR_TX_PIN` | `43` | ESP32 TX → modem RXD GPIO |
| `ML_CELLULAR_RX_PIN` | `44` | ESP32 RX ← modem TXD GPIO |
| `ML_CELLULAR_PWRKEY_PIN` | `-1` | Modem power key GPIO. `-1` = not connected (Waveshare: always-on via USB). LILYGO: GPIO18. |
| `ML_CELLULAR_DTR_PIN` | `-1` | Modem DTR GPIO. `-1` = not connected. LILYGO: GPIO9. |
| `ML_CELLULAR_APN` | Empty | Cellular APN. Examples: `soracom.io`, `america.bics`, `h2g2` |
| `ML_CELLULAR_SIM_PIN` | Empty | SIM card PIN code. Leave empty if no PIN required. |
| `ML_CELLULAR_PPP_USER` | Empty | PPP CHAP username. Leave empty for IMSI-based carriers. Soracom: `sora` |
| `ML_CELLULAR_PPP_PASS` | Empty | PPP CHAP password. Leave empty for IMSI-based carriers. Soracom: `sora` |

#### Network Switching (WiFi ↔ Cellular Failover)

| Option | Default | Description |
|--------|---------|-------------|
| `ML_ENABLE_NET_SWITCH` | `n` | Enable automatic WiFi/cellular switching |
| `ML_NET_SWITCH_WIFI_TIMEOUT_MS` | `30000` | WiFi connect timeout before falling back to cellular |
| `ML_NET_SWITCH_HEALTH_INTERVAL_MS` | `30000` | Health check interval. After 3 consecutive failures, triggers network switch. |
| `ML_NET_SWITCH_FAILBACK_MS` | `120000` | When on cellular, how often to check if WiFi recovered. `0` = disable automatic failback. |

#### HTTP Config Server

| Option | Default | Description |
|--------|---------|-------------|
| `ML_ENABLE_CONFIG_HTTPD` | `n` | Enable web UI at `http://<vpn-ip>/` accessible from any tailnet device |
| `ML_CONFIG_MAX_ALLOWED_PEERS` | `16` | Max peers in DISCO probe allowlist (1-1024). Each entry: 28 bytes in NVS. Empty allowlist = probe all peers. |

### DERP Relay

V2 uses fully dynamic DERP discovery — no manual region configuration needed. On startup, MicroLink:

1. Parses the `DERPMap` from the Tailscale MapResponse (supports up to 32 regions)
2. Selects the optimal home region based on latency
3. Automatically fails over to other regions if the primary becomes unavailable
4. Ensures the ESP32 connects to the same DERP region it advertises as `PreferredDERP`

**Important:** The ESP32 must connect to the same DERP region it advertises. Tailscale peers send packets to whichever DERP region you advertise as your `PreferredDERP`. If there's a mismatch, DISCO PING/PONG packets won't reach your device.

### Custom Coordination Server (Headscale / Ionscale)

MicroLink supports custom coordination servers like [Headscale](https://github.com/juanfont/headscale) and [Ionscale](https://github.com/jsiebens/ionscale). This allows you to run your own private Tailscale-compatible control plane.

**Configuration:** Set the control plane host via the HTTP config server web UI (Device Settings → Control Plane Host) or programmatically via `ctrl_host` in the config struct.

**Server key:** MicroLink automatically fetches the server's Noise public key from the `/key` endpoint via HTTPS. No manual key configuration required.

**Notes:**
- Generate auth keys from your Headscale/Ionscale admin interface, not from Tailscale
- If your custom server uses self-signed certificates, add them to the ESP32's certificate bundle
- MicroLink implements ts2021 — ensure your coordination server supports this version
- DERP discovery is automatic from the server's `DERPMap`

## High-Throughput Mode (Zero-Copy WireGuard)

For applications requiring high data throughput (e.g., video streaming at 30fps+), MicroLink offers an optional zero-copy WireGuard receive mode.

### Configuration

```bash
idf.py menuconfig
# Navigate to: MicroLink V2 Configuration
# Enable: "Enable zero-copy WireGuard receive (high-throughput mode)"
```

### When to Use

| Use Case | Recommended Mode |
|----------|-----------------|
| IoT sensors, heartbeats | Standard (default) |
| Remote control commands | Standard (default) |
| Video streaming (30fps+) | Zero-copy |
| Large file transfers | Zero-copy |

### How It Works

Zero-copy mode uses a raw lwIP PCB callback that runs in `tcpip_thread` and demultiplexes:
- **WireGuard packets** → `wireguardif_network_rx()` directly (zero copy, same thread)
- **DISCO packets** → Lock-free SPSC ring buffer to wg_mgr task
- **STUN responses** → Dedicated buffer for STUN module

This avoids the overhead of BSD socket syscalls and buffer copies, achieving lower latency and higher throughput.

Zero-copy mode contributed by [dj-oyu](https://github.com/dj-oyu/microlink).

## Troubleshooting

### Device not appearing in tailnet
- Check auth key is valid and not expired
- Ensure WiFi is connected (or cellular registered)
- Check coordination server connection in logs
- Try a fresh auth key from https://login.tailscale.com/admin/settings/keys

### `tailscale ping` times out
- Verify DISCO and DERP are enabled in config
- Check DERP connection in serial logs — look for "DERP: connected to region X"
- Look for "PONG sent" in logs
- Ensure the ESP32's advertised `PreferredDERP` matches the region it's actually connected to

### High latency
- DERP relay: 30-150ms (WiFi), 300-600ms (cellular PPP) — this is normal
- Direct connections are faster: 5-50ms (WiFi), 265-390ms (cellular PPP)
- Wait for DISCO to discover a direct path (may take 30-60 seconds)
- If stuck on DERP, check NAT type — symmetric NAT blocks direct connections

### "Failed to parse MapResponse JSON"
- H2 buffer too small for your tailnet size
- Increase `ML_H2_BUFFER_SIZE_KB` and `ML_JSON_BUFFER_SIZE_KB` in menuconfig
- For 300+ peers, use 512KB (default). For 600+, use 1024KB.
- Ensure PSRAM is enabled: `CONFIG_SPIRAM=y`

### PPP connection fails / falls back to AT socket
- Check carrier APN is correct
- For CHAP carriers (Soracom), set `ML_CELLULAR_PPP_USER` and `ML_CELLULAR_PPP_PASS`
- For IMSI-based carriers (EIOT/BICS), leave PPP credentials empty
- Check serial log for "PPP CHAP auth failed" — this triggers automatic AT socket fallback
- AT socket bridge is slower but functional — the fallback is working as intended

### "PSRAM allocation failed"
- Ensure PSRAM is enabled in sdkconfig (see Quick Start section)
- Check that `CONFIG_SPIRAM=y` is set
- Verify your board has PSRAM (most ESP32-S3 dev boards do)

### App partition too small
- Add `CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y` to sdkconfig.defaults
- Clean build: `rm -rf build sdkconfig && idf.py build`

### Cellular modem not responding
- Check UART wiring: ESP32 TX → modem RXD, ESP32 RX ← modem TXD, shared GND
- Modem needs separate USB-C power and 15-30 seconds to boot after power-on
- After SIM swap, power-cycle the modem (not just ESP32)
- Check serial log for AT command responses

### Factory reset
If the device is in a bad state (wrong keys cached, stale peer data):
```c
microlink_factory_reset();  // Call before microlink_init()
```
This erases all NVS-stored keys and peer cache. The device will re-register on next boot.

## Performance & Thermal Optimization

### Thermal Considerations

The ESP32-S3 can get warm during continuous operation, especially with:
- High-frequency polling or data transmission
- Active WiFi + cellular simultaneously
- Verbose debug logging

### Recommendations for Production

1. **Disable debug logging** — reduces CPU load significantly
2. **Use a heatsink** on ESP32-S3 for 24/7 operation
3. **Monitor heap** — use the HTTP config server's system monitor or add periodic logging
4. **Adequate TX intervals** — 30 seconds between heartbeats is sufficient for most applications
5. **DISCO allowlist** — on large tailnets, limit DISCO probing to only the peers you need

### Heap Monitoring

The HTTP config server provides real-time heap monitoring. For standalone monitoring:

```c
static uint32_t last_heap_log = 0;
uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
if (now - last_heap_log > 60000) {  // Every 60 seconds
    ESP_LOGI(TAG, "Free heap: %lu, min: %lu, PSRAM: %lu",
             esp_get_free_heap_size(),
             esp_get_minimum_free_heap_size(),
             heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    last_heap_log = now;
}
```

## Documentation

- [TESTING_GUIDE.md](TESTING_GUIDE.md) — Hardware setup, build, flash, test procedures
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — System design and task model
- [docs/LARGE_TAILNET.md](docs/LARGE_TAILNET.md) — Scaling considerations for 300+ peers
- [docs/TAILSCALE_REFERENCE.md](docs/TAILSCALE_REFERENCE.md) — Tailscale protocol reference patterns

## Acknowledgments

### Projects & Libraries

- [Tailscale](https://tailscale.com/) for the protocol specification
- [Headscale](https://github.com/juanfont/headscale) for open-source coordination server insights
- [WireGuard](https://www.wireguard.com/) for the cryptographic foundation
- [lwIP](https://savannah.nongnu.org/projects/lwip/) for the TCP/IP stack
- [wireguard-lwip](https://github.com/smartalock/wireguard-lwip) for WireGuard-lwIP integration

### Developed By

**[Malone Technologies LLC](https://github.com/Malone-Technologies)**

### Contributors

MicroLink includes improvements from community forks:

- **[dj-oyu](https://github.com/dj-oyu)** — Zero-copy WireGuard receive mode, PONG rate-limiting, adaptive probe intervals, symmetric NAT port spray, and path discovery optimizations. Originally developed for high-throughput video streaming on RDK-X5 smart pet camera.

- **[GrieferPig](https://github.com/GrieferPig)** — WireGuard peer lookup fix to prefer peers with valid keypairs, preventing handshake failures with stale peer references.

## License

MIT License — see [LICENSE](LICENSE)

## Disclaimer

This is an independent implementation created for educational and interoperability purposes. It is not affiliated with or endorsed by Tailscale Inc. Use at your own risk.
