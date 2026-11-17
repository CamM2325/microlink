/**
 * @file microlink.h
 * @brief MicroLink v2 - ESP32 Tailscale Client (Public API)
 *
 * Production-ready Tailscale client for ESP32-S3 with:
 * - Queue-based architecture (no mutex deadlocks)
 * - Dedicated tasks for DERP TX, network I/O, coordination, WireGuard
 * - Rate-limited DISCO (matching native tailscaled timing)
 * - Async STUN (non-blocking)
 * - PSRAM-optimized memory layout
 */

#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle */
typedef struct microlink_s microlink_t;

/* Configuration */
typedef struct {
    const char *auth_key;       /* Tailscale auth key (tskey-auth-...) */
    const char *device_name;    /* Device hostname on the tailnet */
    bool enable_derp;           /* Enable DERP relay (default: true) */
    bool enable_stun;           /* Enable STUN endpoint discovery */
    bool enable_disco;          /* Enable DISCO NAT traversal */
    uint8_t max_peers;          /* Max simultaneous peers (default: 16) */
    int8_t wifi_tx_power_dbm;   /* WiFi TX power in dBm (0 = default 19.5) */

    /* Priority peer: guaranteed a WG slot even when peer table is full.
     * On large tailnets the NVS cache can fill the peer table at boot
     * before the priority peer arrives from MapResponse. When the table
     * is full and a peer matching this IP arrives, the least-recently-used
     * non-priority peer is evicted to make room.
     * Set to 0 to disable (all peers treated equally). */
    uint32_t priority_peer_ip;  /* VPN IP in host byte order (e.g., microlink_parse_ip("100.x.y.z")) */

    /* Optional timing overrides (0 = use defaults) */
    uint32_t disco_heartbeat_ms;    /* DISCO keepalive interval (default: 3000) */
    uint32_t stun_interval_ms;      /* STUN re-probe interval (default: 23000) */
    uint32_t ctrl_watchdog_ms;      /* Control plane watchdog timeout (default: 120000) */

    /* Custom control plane (Headscale / Ionscale). NULL = use the
     * CONFIG_ML_CTRL_HOST / CONFIG_ML_CTRL_NOISE_PUBKEY_HEX build-time
     * values, falling back to Tailscale's. The NVS web-UI override, if
     * present, still wins over both. */
    const char *ctrl_host;          /* Coordination server hostname */
    const uint8_t *ctrl_noise_pubkey; /* Server Noise public key (32 bytes),
                                        e.g. fetched from https://<host>/key?v=131
                                        at provisioning time */

    /* Some headscale-based controllers never respond to the initial
     * Stream=false MapRequest (e.g. ZTL: 60s of zero bytes -> Empty
     * MapResponse -> reconnect loop). The official Tailscale client uses a
     * single Stream=true streaming poll from the start, and the first stream
     * message carries the full netmap (Peers + DERPMap).
     * Setting this to true switches to that scheme (start with Stream=true /
     * OmitPeers=false and take Peers + DERPMap from the first MapResponse).
     * false (default) keeps the existing Stream=false one-shot fetch. */
    bool streaming_map_fetch;

    /* Subnet router / exit node (needs CONFIG_ML_SUBNET_ROUTER). Prefixes,
     * separated by commas or spaces, that this device offers to the
     * tailnet, e.g. "192.168.1.0/24, fd12:3456::/64" (IPv6 needs
     * CONFIG_ML_ROUTER_IPV6). "0.0.0.0/0" offers it as an exit node.
     * Routes take effect once approved in the admin console (or by an
     * autoApprovers policy). Traffic to them is forwarded out of the
     * device's other interface with its address as source (SNAT), like
     * Tailscale's default. NULL = CONFIG_ML_ADVERTISE_ROUTES. The string
     * must stay valid until microlink_init() returns. */
    const char *advertise_routes;
} microlink_config_t;

/* Peer info (read-only snapshot) */
typedef struct {
    uint32_t vpn_ip;
    char hostname[64];
    uint8_t public_key[32];
    bool online;                /* control plane's last Online for this peer;
                                   false if it never reported one */
    bool direct_path;           /* true if communicating via direct UDP */
} microlink_peer_info_t;

/* Connection state */
typedef enum {
    ML_STATE_IDLE = 0,
    ML_STATE_WIFI_WAIT,
    ML_STATE_CONNECTING,
    ML_STATE_REGISTERING,
    ML_STATE_CONNECTED,
    ML_STATE_RECONNECTING,
    ML_STATE_ERROR,
    /* Registration was rejected by the control plane (expired/revoked auth
     * key, or the node awaits authorization). The stack keeps retrying at
     * maximum backoff, but recovery normally needs a new auth key — hosts
     * should surface this to the user as their equivalent of a "re-login"
     * prompt (headless devices have no UI to notice it otherwise). */
    ML_STATE_AUTH_FAILED,
    /* No auth key was given and the control plane wants an interactive
     * login: get the URL with microlink_get_auth_url() and show it (or a QR
     * code of it) to the user. The device keeps waiting for the login and
     * moves on to CONNECTED by itself once it is done. */
    ML_STATE_NEEDS_LOGIN,
} microlink_state_t;

/* Longest login URL microlink_get_auth_url() can return, with the NUL */
#define MICROLINK_AUTH_URL_MAX 256

/* Callback types */
typedef void (*microlink_state_cb_t)(microlink_t *ml, microlink_state_t state, void *user_data);
typedef void (*microlink_peer_cb_t)(microlink_t *ml, const microlink_peer_info_t *peer, void *user_data);
typedef void (*microlink_data_cb_t)(microlink_t *ml, uint32_t src_ip, const uint8_t *data,
                                     size_t len, void *user_data);

/**
 * @brief Factory reset — erase all stored keys and cached peers
 * @return ESP_OK on success
 *
 * Must be called BEFORE microlink_init(). Erases:
 * - Machine key, WireGuard key, DISCO key (NVS namespace "microlink")
 * - Cached peer data (NVS namespace "ml_peers")
 * After reset, next microlink_init() will generate fresh keys.
 */
esp_err_t microlink_factory_reset(void);

/**
 * @brief Initialize MicroLink
 * @param config Configuration (copied internally)
 * @return Handle on success, NULL on failure
 *
 * Creates all internal tasks, queues, and event groups.
 * Does NOT start connecting - call microlink_start() for that.
 */
microlink_t *microlink_init(const microlink_config_t *config);

/**
 * @brief Start connecting to Tailscale
 * @param ml Handle from microlink_init()
 * @return ESP_OK on success,
 *         ESP_ERR_INVALID_STATE if already started or if tasks from a previous
 *         run are still exiting (call microlink_stop() again first),
 *         ESP_FAIL if a task could not be created (the partial start is rolled
 *         back; the handle is left stopped).
 *
 * WiFi must be connected before calling this.
 * Connection proceeds asynchronously - use callbacks or poll state.
 * May be called again after microlink_stop() returned ESP_OK.
 */
esp_err_t microlink_start(microlink_t *ml);

/**
 * @brief Rebind to a new network interface without destroying the session
 * @param ml Handle
 * @return ESP_OK on success
 *
 * Use this when switching between WiFi and cellular (or vice versa).
 * Closes and reopens all sockets on the new interface while preserving:
 * - WireGuard peer state and crypto keys
 * - Peer table and DISCO discovery state
 * - VPN IP assignment
 * - Task state machines
 *
 * The coord and DERP connections will reconnect automatically (~5-10s).
 * Much faster than stop/destroy/init/start which requires full re-registration
 * and MapResponse re-download.
 */
esp_err_t microlink_rebind(microlink_t *ml);

/**
 * @brief Stop and disconnect from Tailscale
 * @param ml Handle
 * @return ESP_OK once every internal task has exited and the per-run
 *         resources (sockets, queued packets, WireGuard interface) are released;
 *         ESP_ERR_TIMEOUT if a task was still blocked in a network call when
 *         CONFIG_ML_STOP_TIMEOUT_MS expired. Nothing is freed in that case;
 *         calling microlink_stop() again resumes the wait.
 *
 * Requests shutdown, unblocks the tasks' blocking socket calls, and waits for
 * the tasks to exit. Safe to call when already stopped. After ESP_OK the
 * handle can be started again with microlink_start().
 */
esp_err_t microlink_stop(microlink_t *ml);

/**
 * @brief Destroy MicroLink instance and free all resources
 * @param ml Handle (NULL-safe)
 *
 * Calls microlink_stop(). If a task is still running after that, the instance
 * is not freed (that would be a use-after-free once the task wakes up): it is
 * parked and freed by a later microlink_init() or microlink_destroy() once the
 * task has exited. Either way the caller must not use the handle again.
 */
void microlink_destroy(microlink_t *ml);

/**
 * @brief Get current connection state
 */
microlink_state_t microlink_get_state(const microlink_t *ml);

/**
 * @brief Check if connected and ready to send/receive
 */
bool microlink_is_connected(const microlink_t *ml);

/**
 * @brief Get our assigned VPN IP
 * @return VPN IP in host byte order, 0 if not yet assigned
 */
uint32_t microlink_get_vpn_ip(const microlink_t *ml);

/**
 * @brief Get the login URL of a pending interactive login
 *
 * Without an auth key (auth_key NULL or ""), the control plane answers the
 * registration with a URL; whoever opens it and logs in adds this device
 * to their tailnet, so show it only to the device's owner (it is a
 * credential until used). The device's keys are kept in NVS, so this is
 * needed once, not on every boot.
 *
 * @param buf     Receives the NUL-terminated URL
 * @param buf_len Size of buf; MICROLINK_AUTH_URL_MAX always fits
 * @return ESP_OK, ESP_ERR_NOT_FOUND if no login is pending,
 *         ESP_ERR_INVALID_SIZE if buf is too small (nothing is copied:
 *         a truncated URL would be useless), ESP_ERR_INVALID_ARG
 */
esp_err_t microlink_get_auth_url(microlink_t *ml, char *buf, size_t buf_len);

/**
 * @brief Your own lwIP IPv6 input hook, when MicroLink forwards IPv6
 *
 * With CONFIG_ML_ROUTER_IPV6, MicroLink implements lwIP's
 * lwip_hook_ip6_input() (for NAT66), so the application cannot. Define this
 * function instead: it is called for every IPv6 packet MicroLink does not
 * consume, after any translation, on tcpip_thread. Return 1 if you consumed
 * (and freed) the packet, 0 to let lwIP process it. The default does nothing.
 */
struct pbuf;
struct netif;
int microlink_ip6_input_hook(struct pbuf *p, struct netif *inp);

/**
 * @brief Get number of known peers
 */
int microlink_get_peer_count(const microlink_t *ml);

/**
 * @brief Get peer info by index
 * @param ml Handle
 * @param index Peer index (0 to peer_count-1)
 * @param info Output peer info (copied)
 * @return ESP_OK if valid index
 */
esp_err_t microlink_get_peer_info(const microlink_t *ml, int index, microlink_peer_info_t *info);

/**
 * @brief Deprecated: always returns ESP_ERR_NOT_SUPPORTED.
 *
 * Earlier versions sent the payload unencrypted over DERP. Use
 * microlink_udp_create()/microlink_udp_send() or microlink_tcp_connect(),
 * which go through the WireGuard tunnel.
 */
esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                          const uint8_t *data, size_t len);

/**
 * @brief Register callbacks
 */
void microlink_set_state_callback(microlink_t *ml, microlink_state_cb_t cb, void *user_data);
void microlink_set_peer_callback(microlink_t *ml, microlink_peer_cb_t cb, void *user_data);
void microlink_set_data_callback(microlink_t *ml, microlink_data_cb_t cb, void *user_data);

/**
 * @brief Convert VPN IP to string
 */
void microlink_ip_to_str(uint32_t ip, char *buf);

/**
 * @brief Parse IP string "A.B.C.D" to host byte order uint32
 * @return IP in host byte order, 0 on error
 */
uint32_t microlink_parse_ip(const char *ip_str);

/**
 * @brief Get default device name based on MAC address
 * @return Static string like "esp32-a1b2c3"
 */
const char *microlink_default_device_name(void);

/**
 * @brief Get device name based on IMEI (cellular modem)
 * @return Static string like "prefix-123456789012345", or NULL if no IMEI available
 *
 * Requires ml_cellular_init() to have been called first.
 * Returns NULL if cellular module is not initialized or IMEI not available.
 */
const char *microlink_imei_device_name(void);

/* ============================================================================
 * MagicDNS — Resolve Tailnet hostnames to VPN IPs
 *
 * Resolves short or FQDN hostnames (e.g., "npc1", "npc1.tail12345.ts.net")
 * against the known peer list. No network calls — lookup only.
 * ========================================================================== */

/**
 * @brief Resolve a tailnet hostname to its VPN IP
 * @param ml Handle
 * @param hostname Short name ("npc1") or FQDN ("npc1.tail12345.ts.net")
 * @return VPN IP in host byte order, 0 if not found
 *
 * Matching rules (in order):
 * 1. Exact match against full peer hostname
 * 2. Prefix match: "npc1" matches "npc1.tail12345.ts.net"
 * 3. Case-insensitive on all matches
 */
uint32_t microlink_resolve(const microlink_t *ml, const char *hostname);

/* ============================================================================
 * UDP Socket API
 *
 * Provides simple UDP send/receive over the Tailscale VPN tunnel.
 * Packets are routed through WireGuard for encryption.
 *
 * Thread safety: send, recv and set_rx_callback may be called from any task,
 * including concurrently on the same socket and from the receive callback.
 * close may be called from any task or from the receive callback, but must
 * not race other calls on the same socket (the handle is invalid once close
 * has been entered).
 * ========================================================================== */

/* Opaque UDP socket handle */
typedef struct microlink_udp_socket microlink_udp_socket_t;

/* UDP receive callback. Runs on the socket's own RX task (priority
 * CONFIG_ML_UDP_RX_TASK_PRIO, 4 KB stack); avoid long blocking work, since at
 * most 4 packets are buffered while it runs. data is only valid during the
 * call. */
typedef void (*microlink_udp_rx_cb_t)(microlink_udp_socket_t *sock,
                                       uint32_t src_ip, uint16_t src_port,
                                       const uint8_t *data, size_t len,
                                       void *user_data);

/**
 * @brief Create a UDP socket bound to the WireGuard VPN IP
 * @param ml Handle
 * @param local_port Port to bind (0 = auto-assign)
 * @return Socket handle, NULL on failure
 *
 * On creation, queues a CallMeMaybe to every peer (sent by the WireGuard
 * manager task, paced at one per 50 ms) to trigger WG handshakes.
 */
microlink_udp_socket_t *microlink_udp_create(microlink_t *ml, uint16_t local_port);

/**
 * @brief Close UDP socket and free resources
 *
 * Stops reception, then waits (up to 5 s) for an in-flight receive callback
 * to return. After close returns the callback is not called again. If the
 * callback is still running at the timeout, or close is called from the
 * callback itself, the socket memory is released when the callback returns.
 */
void microlink_udp_close(microlink_udp_socket_t *sock);

/**
 * @brief Send UDP data to a peer
 * @param sock Socket handle
 * @param dest_ip Destination VPN IP (host byte order)
 * @param dest_port Destination port
 * @param data Payload
 * @param len Payload length (max 1400)
 * @return ESP_OK on success
 */
esp_err_t microlink_udp_send(microlink_udp_socket_t *sock, uint32_t dest_ip,
                              uint16_t dest_port, const void *data, size_t len);

/**
 * @brief Receive UDP data (blocking with timeout)
 * @param sock Socket handle
 * @param src_ip Output source VPN IP (can be NULL)
 * @param src_port Output source port (can be NULL)
 * @param buffer Output buffer
 * @param len In: buffer size, Out: bytes received
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return ESP_OK on success, ESP_ERR_TIMEOUT if timed out
 */
esp_err_t microlink_udp_recv(microlink_udp_socket_t *sock, uint32_t *src_ip,
                              uint16_t *src_port, void *buffer, size_t *len,
                              uint32_t timeout_ms);

/**
 * @brief Register receive callback for immediate packet handling
 * @param sock Socket handle
 * @param cb Callback (NULL to clear)
 * @param user_data Passed to callback
 *
 * When called from another task, returns only after any in-flight call of the
 * previous callback has finished, so its user_data can then be released.
 */
esp_err_t microlink_udp_set_rx_callback(microlink_udp_socket_t *sock,
                                         microlink_udp_rx_cb_t cb, void *user_data);

/**
 * @brief Get local bound port
 */
uint16_t microlink_udp_get_local_port(const microlink_udp_socket_t *sock);

/* ============================================================================
 * TCP Socket API
 *
 * Provides TCP connections over the Tailscale VPN tunnel.
 * Traffic is routed through WireGuard — standard BSD TCP sockets
 * over the encrypted tunnel. Works with any TCP service on a peer
 * (HTTP, Traccar, MQTT, custom protocols, etc).
 * ========================================================================== */

/* Opaque TCP socket handle */
typedef struct microlink_tcp_socket microlink_tcp_socket_t;

/**
 * @brief Connect TCP to a peer over the VPN tunnel
 * @param ml Handle
 * @param dest_ip Destination VPN IP (host byte order)
 * @param dest_port Destination port
 * @param timeout_ms Connection timeout in ms (0 = default 15s)
 * @return Socket handle, NULL on failure
 *
 * Automatically triggers WG handshake if tunnel is not yet established.
 * Retries once if the initial connect fails due to tunnel not ready.
 */
microlink_tcp_socket_t *microlink_tcp_connect(microlink_t *ml, uint32_t dest_ip,
                                                uint16_t dest_port,
                                                uint32_t timeout_ms);

/**
 * @brief Send data over TCP connection
 * @param sock Socket handle
 * @param data Payload
 * @param len Payload length
 * @return ESP_OK on success, ESP_FAIL on error
 *
 * Blocks until all data is sent or an error occurs.
 */
esp_err_t microlink_tcp_send(microlink_tcp_socket_t *sock, const void *data, size_t len);

/**
 * @brief Receive data from TCP connection
 * @param sock Socket handle
 * @param buffer Output buffer
 * @param len Buffer size
 * @param timeout_ms Timeout in ms (0 = use socket default)
 * @return Bytes received (>0), 0 on timeout, -1 on error/disconnect
 */
int microlink_tcp_recv(microlink_tcp_socket_t *sock, void *buffer, size_t len,
                        uint32_t timeout_ms);

/**
 * @brief Check if TCP connection is still alive
 */
bool microlink_tcp_is_connected(const microlink_tcp_socket_t *sock);

/**
 * @brief Close TCP connection and free resources
 */
void microlink_tcp_close(microlink_tcp_socket_t *sock);

#ifdef __cplusplus
}
#endif
