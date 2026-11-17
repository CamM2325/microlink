/**
 * @file ml_config_httpd.h
 * @brief MicroLink HTTP Config Server — Runtime configuration via web UI
 *
 * Provides an HTTP server accessible via the Tailscale VPN IP for:
 * - WiFi/Tailscale/cellular credential management (stored in NVS)
 * - Peer allowlist for DISCO probe filtering (immediate effect, no restart)
 * - Device status and peer list viewing
 *
 * The peer allowlist controls which peers receive outbound DISCO probes.
 * On large tailnets (60+ peers), this prevents wg_mgr flooding and
 * reduces ping latency from 28-1400ms to consistent <100ms.
 *
 * Gated by CONFIG_ML_ENABLE_CONFIG_HTTPD in Kconfig.
 */

#pragma once

#include "sdkconfig.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef CONFIG_ML_ENABLE_CONFIG_HTTPD

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declare — struct tag only, no typedef (microlink.h owns the typedef) */
struct microlink_s;

/* ============================================================================
 * NVS Storage Types (namespace: "ml_config")
 * ========================================================================== */

#define ML_CONFIG_MAX_ALLOWED_PEERS  CONFIG_ML_CONFIG_MAX_ALLOWED_PEERS

/* General settings (NVS key: "settings")
 * Version history:
 *   v1: Original fields (wifi, auth, device, cellular, flags)
 *   v2: Added max_peers, disco_heartbeat_ms, priority_peer_ip,
 *       ctrl_host, debug_flags
 */
#define ML_CONFIG_SETTINGS_VERSION  3

typedef struct __attribute__((packed)) {
    uint8_t  version;               /* Schema version (ML_CONFIG_SETTINGS_VERSION) */

    /* --- v1 fields (do NOT reorder) --- */
    char     wifi_ssid[33];         /* 32 chars + null */
    char     wifi_pass[65];         /* 64 chars + null */
    char     auth_key[96];          /* tskey-auth-... + null */
    char     device_prefix[32];     /* e.g. "sensor" → becomes "sensor-a1b2c3" */
    char     cellular_apn[32];
    char     cellular_sim_pin[16];  /* unused (kept for the blob layout); always
                                     * cleared. The SIM PIN is set in Kconfig
                                     * (CONFIG_ML_CELLULAR_SIM_PIN) only. */
    uint8_t  flags;                 /* bit 0: reserved */

    /* --- v2 fields (appended, zero = use Kconfig default) --- */
    uint8_t  max_peers;             /* 0 = Kconfig default, 1-64 */
    uint16_t disco_heartbeat_ms;    /* 0 = default 3000ms */
    uint32_t priority_peer_ip;      /* VPN IP in host byte order, 0 = none */
    char     ctrl_host[64];         /* Control plane hostname, empty = Tailscale */
    uint8_t  debug_flags;           /* bit 0: verbose DISCO, bit 1: verbose WG,
                                       bit 2: verbose DERP, bit 3: verbose coord */

    /* --- v3 fields --- */
    char     device_name_full[48];  /* Full custom hostname (overrides prefix+MAC).
                                       Empty = use device_prefix + MAC suffix */
    char     ppp_user[32];          /* PPP username (blank = none) */
    char     ppp_pass[32];          /* PPP password (blank = none) */
} ml_config_settings_t;

/* Peer allowlist entry */
typedef struct __attribute__((packed)) {
    uint32_t vpn_ip;                /* VPN IP in host byte order */
    char     label[24];             /* Human-readable label */
} ml_config_peer_entry_t;

/* Peer allowlist (NVS key: "peers") */
typedef struct __attribute__((packed)) {
    uint16_t count;                 /* Number of valid entries (uint16 for >255) */
    ml_config_peer_entry_t entries[ML_CONFIG_MAX_ALLOWED_PEERS];
} ml_config_peer_list_t;

/* WiFi multi-SSID list (NVS key: "wifi_list") */
#define ML_CONFIG_MAX_WIFI_ENTRIES  16

typedef struct __attribute__((packed)) {
    char ssid[33];                  /* 32 chars + null */
    char pass[65];                  /* 64 chars + null */
} ml_config_wifi_entry_t;           /* 98 bytes */

typedef struct __attribute__((packed)) {
    uint8_t count;                  /* Number of entries (0..16) */
    uint8_t active_idx;             /* Currently connected index, 0xFF = none */
    ml_config_wifi_entry_t entries[ML_CONFIG_MAX_WIFI_ENTRIES];
} ml_config_wifi_list_t;            /* 1570 bytes max */

/* Opaque context */
typedef struct ml_config_ctx ml_config_ctx_t;

/* ============================================================================
 * Lifecycle API
 * ========================================================================== */

/**
 * @brief Initialize config module: open NVS, load settings + peer list
 * @return Context handle (PSRAM-allocated), NULL on failure
 *
 * Call during microlink_init(). Settings are loaded from NVS and can
 * override Kconfig defaults for WiFi/auth key at boot.
 */
ml_config_ctx_t *ml_config_httpd_init(void);

/**
 * @brief Start the HTTP server
 * @param ctx Context from ml_config_httpd_init()
 * @param ml MicroLink handle (for peer/status queries)
 * @return ESP_OK on success
 *
 * Call after microlink_start() when VPN IP is available.
 * Binds to port 80 on all interfaces.
 */
esp_err_t ml_config_httpd_start(ml_config_ctx_t *ctx, struct microlink_s *ml);

/**
 * @brief Stop HTTP server
 */
void ml_config_httpd_stop(ml_config_ctx_t *ctx);

/**
 * @brief Deinit: close NVS, free memory
 */
void ml_config_httpd_deinit(ml_config_ctx_t *ctx);

/* ============================================================================
 * Peer Filter API (called from wg_mgr task, thread-safe)
 * ========================================================================== */

/**
 * @brief Check if a peer VPN IP is in the allowlist
 * @param ctx Config context (NULL-safe: returns true)
 * @param vpn_ip VPN IP in host byte order
 * @return true if peer is allowed (filter disabled OR IP in list)
 *
 * Thread-safe: fast path reads atomic flag (no lock),
 * slow path uses mutex with 5ms timeout (fail-open).
 */
bool ml_config_peer_is_allowed(const ml_config_ctx_t *ctx, uint32_t vpn_ip);

/* ============================================================================
 * Settings Query API (for boot-time override of Kconfig defaults)
 * ========================================================================== */

const char *ml_config_get_wifi_ssid(const ml_config_ctx_t *ctx);
const char *ml_config_get_wifi_pass(const ml_config_ctx_t *ctx);
const char *ml_config_get_auth_key(const ml_config_ctx_t *ctx);
const char *ml_config_get_device_prefix(const ml_config_ctx_t *ctx);

/* v2 getters (return 0/NULL = use Kconfig default) */
uint8_t     ml_config_get_max_peers(const ml_config_ctx_t *ctx);
uint16_t    ml_config_get_disco_heartbeat_ms(const ml_config_ctx_t *ctx);
uint32_t    ml_config_get_priority_peer_ip(const ml_config_ctx_t *ctx);
const char *ml_config_get_ctrl_host(const ml_config_ctx_t *ctx);
uint8_t     ml_config_get_debug_flags(const ml_config_ctx_t *ctx);

/* v3 getter — full custom device name (overrides prefix+MAC) */
const char *ml_config_get_device_name_full(const ml_config_ctx_t *ctx);

/**
 * @brief Read WiFi credentials from NVS without full config init
 *
 * Lightweight helper for early boot: reads NVS settings blob and copies
 * WiFi SSID/password into caller-provided buffers. Returns true if NVS
 * had saved WiFi credentials (non-empty SSID).
 *
 * Call BEFORE wifi_init() in the example app to override Kconfig defaults.
 */
bool ml_config_get_nvs_wifi(char *ssid, size_t ssid_len,
                             char *pass, size_t pass_len);

/**
 * @brief Read PPP credentials from NVS settings blob
 *
 * Lightweight helper for boot: reads NVS settings and copies PPP
 * username/password into caller-provided buffers. Returns true if
 * NVS had non-empty PPP credentials.
 */
bool ml_config_get_nvs_ppp(char *user, size_t user_len,
                            char *pass, size_t pass_len);

/**
 * @brief Read cellular APN from NVS settings blob
 *
 * Lightweight helper for boot: reads NVS settings and copies APN
 * into caller-provided buffer. Returns true if NVS had non-empty APN.
 */
bool ml_config_get_nvs_apn(char *apn, size_t apn_len);

/**
 * @brief Read WiFi multi-SSID list from NVS
 *
 * Returns the priority-ordered list of WiFi networks configured via the web UI.
 * Call at boot to get the full list for round-robin connection attempts.
 * Falls back to settings blob WiFi if wifi_list NVS key doesn't exist.
 *
 * @param list Output: populated WiFi list
 * @return true if list was loaded (count > 0)
 */
bool ml_config_get_wifi_list(ml_config_wifi_list_t *list);

#ifdef __cplusplus
}
#endif

#else /* !CONFIG_ML_ENABLE_CONFIG_HTTPD */

/* Stubs when config httpd is disabled */
typedef void ml_config_ctx_t;

/* WiFi list type needed for stub API */
#ifndef ML_CONFIG_MAX_WIFI_ENTRIES
#define ML_CONFIG_MAX_WIFI_ENTRIES  16
typedef struct __attribute__((packed)) {
    char ssid[33];
    char pass[65];
} ml_config_wifi_entry_t;
typedef struct __attribute__((packed)) {
    uint8_t count;
    uint8_t active_idx;
    ml_config_wifi_entry_t entries[ML_CONFIG_MAX_WIFI_ENTRIES];
} ml_config_wifi_list_t;
#endif

static inline ml_config_ctx_t *ml_config_httpd_init(void) { return NULL; }
static inline int ml_config_httpd_start(ml_config_ctx_t *ctx, void *ml) { (void)ctx; (void)ml; return 0; }
static inline void ml_config_httpd_stop(ml_config_ctx_t *ctx) { (void)ctx; }
static inline void ml_config_httpd_deinit(ml_config_ctx_t *ctx) { (void)ctx; }
static inline bool ml_config_peer_is_allowed(const ml_config_ctx_t *ctx, uint32_t ip) { (void)ctx; (void)ip; return true; }
static inline bool ml_config_get_nvs_wifi(char *s, size_t sl, char *p, size_t pl) { (void)s;(void)sl;(void)p;(void)pl; return false; }
static inline bool ml_config_get_nvs_ppp(char *u, size_t ul, char *p, size_t pl) { (void)u;(void)ul;(void)p;(void)pl; return false; }
static inline bool ml_config_get_nvs_apn(char *a, size_t al) { (void)a;(void)al; return false; }
static inline bool ml_config_get_wifi_list(ml_config_wifi_list_t *l) { (void)l; return false; }

/* Getter stubs (all return NULL/0 when config httpd disabled) */
static inline const char *ml_config_get_wifi_ssid(const ml_config_ctx_t *c) { (void)c; return NULL; }
static inline const char *ml_config_get_wifi_pass(const ml_config_ctx_t *c) { (void)c; return NULL; }
static inline const char *ml_config_get_auth_key(const ml_config_ctx_t *c) { (void)c; return NULL; }
static inline const char *ml_config_get_device_prefix(const ml_config_ctx_t *c) { (void)c; return NULL; }
static inline const char *ml_config_get_device_name_full(const ml_config_ctx_t *c) { (void)c; return NULL; }
static inline uint8_t ml_config_get_max_peers(const ml_config_ctx_t *c) { (void)c; return 0; }
static inline uint16_t ml_config_get_disco_heartbeat_ms(const ml_config_ctx_t *c) { (void)c; return 0; }
static inline uint32_t ml_config_get_priority_peer_ip(const ml_config_ctx_t *c) { (void)c; return 0; }
static inline const char *ml_config_get_ctrl_host(const ml_config_ctx_t *c) { (void)c; return NULL; }
static inline uint8_t ml_config_get_debug_flags(const ml_config_ctx_t *c) { (void)c; return 0; }

#endif /* CONFIG_ML_ENABLE_CONFIG_HTTPD */
