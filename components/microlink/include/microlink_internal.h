/**
 * @file microlink_internal.h
 * @brief MicroLink v2 Internal Types and Task Communication
 *
 * Architecture: 5 FreeRTOS tasks communicating via queues and event groups.
 * No shared mutable state between tasks - each owns its data exclusively.
 *
 * Tasks:
 *   net_io   (Core 0, pri 6)  - Unified select() on all sockets
 *   derp_tx  (Core 0, pri 7)  - Sole DERP TLS writer
 *   coord    (Core 1, pri 5)  - Control plane (Noise, HTTP/2, registration)
 *   wg_mgr   (Core 1, pri 7)  - WireGuard + DISCO + peer management
 *   app      (unpinned, pri 3) - User application (external, not ours)
 */

#pragma once

#include "microlink.h"
#include "ml_config_httpd.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_heap_caps.h"

#ifdef CONFIG_ML_ZERO_COPY_WG
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/* Task configuration */
#define ML_TASK_NET_IO_STACK    (8 * 1024)
#define ML_TASK_NET_IO_PRIO     7
#define ML_TASK_NET_IO_CORE     0

#define ML_TASK_DERP_TX_STACK   (14 * 1024)
#define ML_TASK_DERP_TX_PRIO    5
#define ML_TASK_DERP_TX_CORE    0

#define ML_TASK_COORD_STACK     (12 * 1024)
#define ML_TASK_COORD_PRIO      5
#define ML_TASK_COORD_CORE      1

#define ML_TASK_WG_MGR_STACK    (8 * 1024)
#define ML_TASK_WG_MGR_PRIO     7
#define ML_TASK_WG_MGR_CORE     1

/* Queue depths */
#define ML_DERP_TX_QUEUE_DEPTH  16
#define ML_DISCO_RX_QUEUE_DEPTH 8
#define ML_WG_RX_QUEUE_DEPTH    8
#define ML_STUN_RX_QUEUE_DEPTH  4
#define ML_COORD_CMD_QUEUE_DEPTH 4
#define ML_PEER_UPDATE_QUEUE_DEPTH 400

/* Protocol limits */
#define ML_MAX_PEERS            CONFIG_ML_MAX_PEERS
#define ML_MAX_ENDPOINTS        8
#define ML_MAX_PACKET_SIZE      1500
#define ML_DERP_MAX_FRAME       (ML_MAX_PACKET_SIZE + 64)

/* DERP */
#define ML_DERP_REGION          9       /* Dallas (dfw) */
#define ML_DERP_HOST            "derp9e.tailscale.com"
#define ML_DERP_PORT            443

/* Tailscale control plane */
#define ML_CTRL_HOST            "controlplane.tailscale.com"
#define ML_CTRL_PORT            443
#define ML_CTRL_PROTOCOL_VER    131

/* DISCO timing (from tailscaled - MUST match for correct behavior) */
#define ML_DISCO_PING_INTERVAL_MS       5000
#define ML_DISCO_HEARTBEAT_MS           3000
#define ML_DISCO_TRUST_DURATION_MS      15000
#define ML_DISCO_PING_TIMEOUT_MS        5000
#define ML_DISCO_UPGRADE_INTERVAL_MS    15000
#define ML_DISCO_SESSION_ACTIVE_MS      45000

/* STUN servers (Tailscale primary, Google fallback) */
#define ML_STUN_PRIMARY_HOST    "derp9.tailscale.com"
#define ML_STUN_PRIMARY_PORT    3478
#define ML_STUN_FALLBACK_HOST   "stun.l.google.com"
#define ML_STUN_FALLBACK_PORT   19302
#define ML_STUN_MAX_RETRIES     3
#define ML_STUN_RETRY_INTERVAL_MS   2000

/* STUN timing */
#define ML_STUN_RETRANSMIT_MS           100
#define ML_STUN_TOTAL_TIMEOUT_MS        5000
#define ML_STUN_RESTUN_INTERVAL_MS      23000

/* Control plane timing */
#define ML_CTRL_WATCHDOG_MS             120000
#define ML_CTRL_BACKOFF_MAX_MS          30000
#define ML_CTRL_KEEPALIVE_MS            60000

/* Large tailnet buffer sizes (PSRAM-allocated, configurable via menuconfig) */
#define ML_H2_BUFFER_SIZE       (CONFIG_ML_H2_BUFFER_SIZE_KB * 1024)
#define ML_JSON_BUFFER_SIZE     (CONFIG_ML_JSON_BUFFER_SIZE_KB * 1024)

/* Noise protocol */
#define ML_NOISE_KEY_LEN        32
#define ML_NOISE_MAC_LEN        16
#define ML_NOISE_NONCE_LEN      12
#define ML_NOISE_HASH_LEN       32

/* ============================================================================
 * Zero-Copy WG Types (Kconfig: CONFIG_ML_ZERO_COPY_WG)
 *
 * When enabled, the DISCO UDP socket uses a raw lwIP PCB callback instead of
 * a BSD socket. WG packets go directly to wireguardif_network_rx() (zero copy).
 * DISCO packets are buffered in a lock-free SPSC ring for the wg_mgr task.
 * ========================================================================== */

#ifdef CONFIG_ML_ZERO_COPY_WG

#define ML_ZC_DISCO_RING_SIZE   16      /* Must be power of 2 */
#define ML_ZC_DISCO_MAX_PKT     256     /* Max DISCO packet size in ring */
#define ML_ZC_TX_POOL_SIZE      24      /* Outbound send pool depth */

/* SPSC ring entry for DISCO packets (PCB callback → wg_mgr task) */
typedef struct {
    uint8_t data[ML_ZC_DISCO_MAX_PKT];
    uint16_t len;
    uint32_t src_ip_nbo;    /* Network byte order (from lwIP) */
    uint16_t src_port;      /* Host byte order (from lwIP) */
} ml_zc_disco_entry_t;

/* Outbound TX context for tcpip_callback send */
typedef struct {
    struct udp_pcb *pcb;
    uint8_t data[ML_MAX_PACKET_SIZE];
    uint16_t len;
    ip_addr_t dest;
    uint16_t port;
} ml_zc_tx_ctx_t;

/* Zero-copy state embedded in microlink_s */
typedef struct {
    struct udp_pcb *pcb;            /* Raw UDP PCB (replaces disco_sock4) */
    uint16_t local_port;            /* Bound port */

    /* DISCO RX ring buffer (lock-free SPSC) */
    ml_zc_disco_entry_t rx_ring[ML_ZC_DISCO_RING_SIZE];
    volatile uint8_t rx_head;       /* Written by tcpip_thread */
    volatile uint8_t rx_tail;       /* Written by wg_mgr task */

    /* TX send pool (microlink → tcpip_thread) */
    ml_zc_tx_ctx_t tx_pool[ML_ZC_TX_POOL_SIZE];
    volatile uint8_t tx_head;       /* Written by wg_mgr task */
    volatile uint8_t tx_tail;       /* Written by tcpip_thread */
} ml_zerocopy_t;

#endif /* CONFIG_ML_ZERO_COPY_WG */

/* ============================================================================
 * Event Group Bits
 * ========================================================================== */

#define ML_EVT_WIFI_CONNECTED       BIT0
#define ML_EVT_COORD_REGISTERED     BIT1
#define ML_EVT_DERP_CONNECTED       BIT2
#define ML_EVT_WG_READY             BIT3
#define ML_EVT_PEERS_AVAILABLE      BIT4
#define ML_EVT_STUN_COMPLETE        BIT5
#define ML_EVT_SHUTDOWN_REQUEST     BIT6
#define ML_EVT_DERP_RECONNECT       BIT7
#define ML_EVT_DERP_CONNECT_REQ     BIT8

/* ============================================================================
 * Queue Message Types
 * ========================================================================== */

/* DERP TX queue item - packet to send via DERP relay */
typedef struct {
    uint8_t dest_pubkey[32];    /* Destination peer's public key */
    uint8_t *data;              /* Heap-allocated payload (caller frees on failure) */
    size_t len;                 /* Payload length */
    uint8_t frame_type;         /* DERP frame type (0x04 = SendPacket) */
} ml_derp_tx_item_t;

/* Received packet (from net_io to disco/wg queues) */
typedef struct {
    uint8_t *data;              /* Heap-allocated packet data */
    size_t len;                 /* Packet length */
    uint32_t src_ip;            /* Source IP (for UDP packets) */
    uint16_t src_port;          /* Source port (for UDP packets) */
    uint8_t src_pubkey[32];     /* Source peer key (for DERP packets) */
    bool via_derp;              /* true if received via DERP, false if direct UDP */
} ml_rx_packet_t;

/* Coordination command */
typedef enum {
    ML_CMD_CONNECT,             /* Start registration */
    ML_CMD_DISCONNECT,          /* Graceful disconnect */
    ML_CMD_UPDATE_ENDPOINTS,    /* Send endpoint update to control plane */
    ML_CMD_FORCE_RECONNECT,     /* Force reconnection (after DERP failure, etc.) */
} ml_coord_cmd_t;

/* Peer update (from coord to wg_mgr) */
typedef struct {
    enum {
        ML_PEER_ADD,
        ML_PEER_REMOVE,
        ML_PEER_UPDATE_ENDPOINT,
    } action;
    uint32_t vpn_ip;
    uint8_t public_key[32];
    uint8_t disco_key[32];
    char hostname[64];
    uint16_t derp_region;
    /* Endpoints */
    struct {
        uint32_t ip;
        uint16_t port;
        bool is_ipv6;
    } endpoints[ML_MAX_ENDPOINTS];
    int endpoint_count;
} ml_peer_update_t;

/* ============================================================================
 * Peer State (owned exclusively by wg_mgr task)
 * ========================================================================== */

typedef struct {
    /* Identity */
    uint32_t vpn_ip;
    uint8_t public_key[32];
    uint8_t disco_key[32];
    char hostname[64];
    bool active;

    /* Endpoints */
    struct {
        uint32_t ip;
        uint16_t port;
        bool is_ipv6;
    } endpoints[ML_MAX_ENDPOINTS];
    int endpoint_count;
    uint16_t derp_region;

    /* DISCO state (rate limiting) */
    uint64_t last_ping_sent_ms;     /* Last DISCO ping we sent */
    uint64_t last_pong_recv_ms;     /* Last DISCO pong we received */
    uint64_t trust_until_ms;        /* Direct path trusted until */
    uint64_t last_send_ms;          /* Last data sent to this peer */
    uint64_t last_upgrade_ms;       /* Last path upgrade attempt */

    /* Best direct path */
    uint32_t best_ip;
    uint16_t best_port;
    bool has_direct_path;

    /* WireGuard peer index in wireguard-lwip */
    int wg_peer_index;

    /* On-demand handshake: tried once on first DISCO direct path discovery */
    bool tried_initial_handshake;
} ml_peer_t;

/* ============================================================================
 * DERP Map Types (parsed from MapResponse, used by coord + STUN)
 * ========================================================================== */

#define ML_MAX_DERP_REGIONS     32
#define ML_MAX_DERP_NODES       4

typedef struct {
    char hostname[64];
    char ipv4[16];
    char ipv6[46];
    uint16_t stun_port;     /* 0 = default 3478 */
    uint16_t derp_port;     /* 0 = default 443 */
    bool stun_only;         /* true if node only serves STUN, not DERP */
} ml_derp_node_t;

typedef struct {
    uint16_t region_id;
    char code[8];           /* e.g. "dfw", "nyc", "sfo" */
    ml_derp_node_t nodes[ML_MAX_DERP_NODES];
    uint8_t node_count;
    bool avoid;             /* true if region should be avoided */
} ml_derp_region_t;

/* ============================================================================
 * Noise Protocol State (owned exclusively by coord task)
 * ========================================================================== */

typedef struct {
    uint8_t h[ML_NOISE_HASH_LEN];
    uint8_t ck[ML_NOISE_HASH_LEN];
    uint8_t local_static_private[32];
    uint8_t local_static_public[32];
    uint8_t local_ephemeral_private[32];
    uint8_t local_ephemeral_public[32];
    uint8_t remote_static_public[32];
    uint8_t tx_key[ML_NOISE_KEY_LEN];
    uint8_t rx_key[ML_NOISE_KEY_LEN];
    uint64_t tx_nonce;
    uint64_t rx_nonce;
    bool handshake_complete;
} ml_noise_state_t;

/* ============================================================================
 * DERP Connection State
 * ========================================================================== */

typedef struct {
    int sockfd;                     /* Raw TCP socket */
    mbedtls_ssl_context ssl;        /* TLS context (owned exclusively by DERP I/O task) */
    mbedtls_ssl_config ssl_conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    bool connected;
    uint64_t last_recv_ms;          /* For keepalive watchdog */
} ml_derp_conn_t;

/* ============================================================================
 * Main Context
 * ========================================================================== */

struct microlink_s {
    /* Configuration (immutable after init) */
    microlink_config_t config;

    /* State (atomic reads from any task, writes only from coord) */
    volatile microlink_state_t state;
    volatile uint32_t vpn_ip;

    /* Event group (cross-task synchronization) */
    EventGroupHandle_t events;

    /* Task handles */
    TaskHandle_t net_io_task;
    TaskHandle_t derp_tx_task;
    TaskHandle_t coord_task;
    TaskHandle_t wg_mgr_task;

    /* Queues */
    QueueHandle_t derp_tx_queue;        /* -> derp_tx task */
    QueueHandle_t disco_rx_queue;       /* net_io -> wg_mgr */
    QueueHandle_t wg_rx_queue;          /* net_io -> wg_mgr */
    QueueHandle_t stun_rx_queue;        /* net_io -> coord */
    QueueHandle_t coord_cmd_queue;      /* any -> coord */
    QueueHandle_t peer_update_queue;    /* coord -> wg_mgr */

    /* Keys (loaded at init, read-only after) */
    uint8_t machine_private_key[32];    /* Noise machine key */
    uint8_t machine_public_key[32];
    uint8_t wg_private_key[32];         /* WireGuard key */
    uint8_t wg_public_key[32];
    uint8_t disco_private_key[32];      /* DISCO key */
    uint8_t disco_public_key[32];

    /* DERP connection (owned exclusively by DERP I/O task after connect) */
    /* Connection setup by coord task, then handed to DERP I/O task */
    ml_derp_conn_t derp;

    /* Sockets for net_io select() loop */
    int disco_sock4;                    /* UDP socket for DISCO + direct WG */
    int disco_sock6;                    /* IPv6 UDP socket (-1 if unavailable) */
    int stun_sock;                      /* UDP socket for STUN */
    uint16_t disco_local_port;          /* Bound port for disco_sock4 */

    /* Coordination socket (owned exclusively by coord task) */
    int coord_sock;
    uint32_t h2_next_stream_id;         /* Next H2 stream ID for endpoint updates (odd, starts at 7) */

    /* WireGuard netif (owned exclusively by wg_mgr task) */
    void *wg_netif;

    /* Peers (owned exclusively by wg_mgr task) */
    ml_peer_t peers[ML_MAX_PEERS];
    int peer_count;

    /* STUN results (written by coord, read by coord only) */
    uint32_t stun_public_ip;
    uint16_t stun_public_port;

    /* STUN server cache (pre-resolved IPs, host byte order) */
    uint32_t stun_primary_ip;       /* derp9.tailscale.com resolved IPv4 */
    uint32_t stun_fallback_ip;      /* stun.l.google.com resolved IPv4 */
    uint8_t stun_retry_count;       /* Retries on current server */
    bool stun_using_fallback;       /* true if probing fallback server */
    uint64_t stun_last_probe_ms;    /* Timestamp of last probe sent */

    /* IPv6 STUN */
    int stun_sock6;                 /* IPv6 UDP socket for STUN (-1 if unavailable) */
    uint8_t stun_primary_ip6[16];   /* derp9.tailscale.com resolved IPv6 */
    uint8_t stun_public_ip6[16];    /* Our public IPv6 from STUN */
    uint16_t stun_public_port6;     /* Our public IPv6 port from STUN */
    bool stun_has_ipv6;             /* true if IPv6 STUN result available */

    /* Symmetric NAT detection */
    uint16_t stun_secondary_port;   /* Mapped port from second STUN server */
    bool stun_nat_checked;          /* true if symmetric NAT check completed */
    bool nat_mapping_varies;        /* true = symmetric NAT (direct won't work) */

    /* DERP map (parsed from MapResponse, owned by coord task) */
    ml_derp_region_t derp_regions[ML_MAX_DERP_REGIONS];
    uint8_t derp_region_count;
    uint16_t derp_home_region;      /* Our PreferredDERP region */

    /* Key expiry (parsed from MapResponse self-node) */
    int64_t key_expiry_epoch;       /* Unix epoch seconds, 0 = no expiry */
    bool key_expired;               /* true if Node.Expired == true */

    /* Resolved timing (set during init from config, 0 = default) */
    uint32_t t_disco_heartbeat_ms;
    uint32_t t_stun_interval_ms;
    uint32_t t_ctrl_watchdog_ms;

    /* Callbacks */
    microlink_state_cb_t state_cb;
    void *state_cb_data;
    microlink_peer_cb_t peer_cb;
    void *peer_cb_data;
    microlink_data_cb_t data_cb;
    void *data_cb_data;

    /* HTTP Config Server (peer allowlist, runtime settings) */
    ml_config_ctx_t *config_httpd;

    /* NVS-backed config string storage (auth_key/device_name pointers in
     * microlink_config_t are redirected here when NVS settings exist) */
    char nvs_auth_key[96];
    char nvs_device_name[48];

    /* Control plane host override (empty = use ML_CTRL_HOST default).
     * Set from NVS at boot for Headscale/Ionscale/custom coordinators. */
    char ctrl_host[64];

    /* Debug flags (bitmask from NVS, checked at runtime for verbose logging) */
    uint8_t debug_flags;  /* bit 0: DISCO, bit 1: WG, bit 2: DERP, bit 3: coord */

#ifdef CONFIG_ML_ZERO_COPY_WG
    /* Zero-copy WG: raw PCB replaces disco_sock4 BSD socket */
    ml_zerocopy_t zc;
#endif
};

/* ============================================================================
 * Internal Function Declarations (per-module)
 * ========================================================================== */

/* ml_net_io.c */
void ml_net_io_task(void *arg);

/* ml_derp.c */
void ml_derp_tx_task(void *arg);
esp_err_t ml_derp_connect(microlink_t *ml);
void ml_derp_disconnect(microlink_t *ml);
esp_err_t ml_derp_queue_send(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len);

/* ml_coord.c */
void ml_coord_task(void *arg);

/* ml_wg_mgr.c */
void ml_wg_mgr_task(void *arg);
void ml_wg_mgr_send_cmm(microlink_t *ml, uint32_t peer_vpn_ip);
esp_err_t ml_wg_mgr_trigger_handshake(microlink_t *ml, uint32_t dest_vpn_ip);
bool ml_wg_mgr_peer_is_up(microlink_t *ml, uint32_t vpn_ip);
void ml_wg_mgr_update_transport(microlink_t *ml);

/* ml_stun.c */
esp_err_t ml_stun_resolve_servers(microlink_t *ml);
esp_err_t ml_stun_send_probe(microlink_t *ml, const char *server, uint16_t port);
esp_err_t ml_stun_send_probe_to(microlink_t *ml, uint32_t server_ip, uint16_t port);
esp_err_t ml_stun_send_probe_ipv6(microlink_t *ml, const uint8_t *server_ip6, uint16_t port);
bool ml_stun_parse_response(const uint8_t *data, size_t len,
                             uint32_t *out_ip, uint16_t *out_port);
bool ml_stun_parse_response_ipv6(const uint8_t *data, size_t len,
                                  uint8_t *out_ip6, uint16_t *out_port);

/* ml_noise.c */
void ml_noise_init(ml_noise_state_t *state,
                    const uint8_t *local_private, const uint8_t *local_public,
                    const uint8_t *remote_public);
esp_err_t ml_noise_write_msg1(ml_noise_state_t *state, uint8_t *out, size_t *out_len);
esp_err_t ml_noise_read_msg2(ml_noise_state_t *state, const uint8_t *msg, size_t len);
esp_err_t ml_noise_encrypt(const uint8_t *key, uint64_t nonce,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *ciphertext);
esp_err_t ml_noise_decrypt(const uint8_t *key, uint64_t nonce,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *ciphertext, size_t ct_len,
                            uint8_t *plaintext);

/* ml_h2.c */
int ml_h2_build_headers_frame(uint8_t *out, size_t out_size,
                               const char *method, const char *path,
                               const char *authority, const char *content_type,
                               uint32_t stream_id, bool end_stream);
int ml_h2_build_data_frame(uint8_t *out, size_t out_size,
                            const uint8_t *data, size_t data_len,
                            uint32_t stream_id, bool end_stream);
int ml_h2_build_preface(uint8_t *out, size_t out_size);
int ml_h2_build_settings_ack(uint8_t *out, size_t out_size);
int ml_h2_build_window_update(uint8_t *out, size_t out_size,
                               uint32_t stream_id, uint32_t increment);

/* ml_peer_nvs.c */
esp_err_t ml_peer_nvs_init(void);
void ml_peer_nvs_deinit(void);
esp_err_t ml_peer_nvs_save(const ml_peer_t *peer);
int ml_peer_nvs_load_all(ml_peer_t *peers, int max_peers);
esp_err_t ml_peer_nvs_clear(void);

#ifdef CONFIG_ML_ZERO_COPY_WG
/* ml_zerocopy.c */
esp_err_t ml_zerocopy_init(microlink_t *ml);
void ml_zerocopy_deinit(microlink_t *ml);
esp_err_t ml_zerocopy_send(microlink_t *ml, const uint8_t *data, size_t len,
                            uint32_t dest_ip, uint16_t dest_port);
#endif

/* Utility */
uint64_t ml_get_time_ms(void);

/* ============================================================================
 * Network Socket Wrappers — Route through AT sockets when cellular active
 *
 * These inline functions check ml_at_socket_is_ready() and route socket calls
 * to either the normal BSD socket API (WiFi/lwIP) or the AT socket bridge
 * (cellular SIM7600 internal TCP/IP stack).
 * ========================================================================== */

#include "ml_at_socket.h"

#ifdef CONFIG_ML_ENABLE_CELLULAR
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

static inline int ml_socket(int domain, int type, int protocol) {
    if (ml_at_socket_is_ready() && (domain == AF_INET || domain == AF_INET6))
        return ml_at_socket(domain, type, protocol);
    return socket(domain, type, protocol);
}

static inline int ml_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_connect(fd, addr, len);
    return connect(fd, addr, len);
}

static inline ssize_t ml_send(int fd, const void *buf, size_t len, int flags) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_send(fd, buf, len, flags);
    return send(fd, buf, len, flags);
}

static inline ssize_t ml_recv(int fd, void *buf, size_t len, int flags) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_recv(fd, buf, len, flags);
    return recv(fd, buf, len, flags);
}

static inline ssize_t ml_sendto(int fd, const void *buf, size_t len, int flags,
                                 const struct sockaddr *addr, socklen_t addrlen) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_sendto(fd, buf, len, flags, addr, addrlen);
    return sendto(fd, buf, len, flags, addr, addrlen);
}

static inline ssize_t ml_recvfrom(int fd, void *buf, size_t len, int flags,
                                    struct sockaddr *addr, socklen_t *addrlen) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_recvfrom(fd, buf, len, flags, addr, addrlen);
    return recvfrom(fd, buf, len, flags, addr, addrlen);
}

static inline int ml_close_sock(int fd) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_close(fd);
    return close(fd);
}

static inline int ml_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_bind(fd, addr, len);
    return bind(fd, addr, len);
}

static inline int ml_setsockopt(int fd, int level, int optname,
                                  const void *optval, socklen_t optlen) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_setsockopt(fd, level, optname, optval, optlen);
    return setsockopt(fd, level, optname, optval, optlen);
}

static inline int ml_fcntl(int fd, int cmd, int arg) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_fcntl(fd, cmd, arg);
    return fcntl(fd, cmd, arg);
}

static inline int ml_select_fds(int nfds, fd_set *rd, fd_set *wr,
                                  fd_set *ex, struct timeval *tv) {
    /* If any FD in the sets is an AT socket, use AT select */
    if (ml_at_socket_is_ready() && nfds > ML_AT_SOCK_FD_BASE)
        return ml_at_select(nfds, rd, wr, ex, tv);
    return select(nfds, rd, wr, ex, tv);
}

static inline int ml_getaddrinfo(const char *host, const char *svc,
                                   const struct addrinfo *hints,
                                   struct addrinfo **res) {
    if (ml_at_socket_is_ready())
        return ml_at_getaddrinfo(host, svc, hints, res);
    return getaddrinfo(host, svc, hints, res);
}

static inline void ml_freeaddrinfo(struct addrinfo *res) {
    /* AT socket addrinfo is also malloc'd, free works for both */
    if (ml_at_socket_is_ready()) {
        ml_at_freeaddrinfo(res);
        return;
    }
    freeaddrinfo(res);
}

/* write/read for mbedTLS BIO compatibility */
static inline ssize_t ml_write_sock(int fd, const void *buf, size_t len) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_write(fd, buf, len);
    return write(fd, buf, len);
}

static inline ssize_t ml_read_sock(int fd, void *buf, size_t len) {
    if (ml_at_socket_is_at_fd(fd))
        return ml_at_read(fd, buf, len);
    return read(fd, buf, len);
}

#else
/* Non-cellular builds: direct pass-through (zero overhead) */
#define ml_socket       socket
#define ml_connect      connect
#define ml_send         send
#define ml_recv         recv
#define ml_sendto       sendto
#define ml_recvfrom     recvfrom
#define ml_close_sock   close
#define ml_bind         bind
#define ml_setsockopt   setsockopt
#define ml_fcntl        fcntl
#define ml_select_fds   select
#define ml_getaddrinfo  getaddrinfo
#define ml_freeaddrinfo freeaddrinfo
#define ml_write_sock   write
#define ml_read_sock    read
#endif /* CONFIG_ML_ENABLE_CELLULAR */

/* PSRAM allocation helper */
static inline void *ml_psram_malloc(size_t size) {
    void *ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ptr) ptr = malloc(size);
    return ptr;
}

static inline void *ml_psram_calloc(size_t n, size_t size) {
    void *ptr = heap_caps_calloc(n, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ptr) ptr = calloc(n, size);
    return ptr;
}

#ifdef __cplusplus
}
#endif
