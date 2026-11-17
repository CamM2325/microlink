/**
 * @file ml_config_httpd.c
 * @brief MicroLink HTTP Config Server
 *
 * Runtime configuration via web UI served on the Tailscale VPN IP.
 * Settings persist in NVS namespace "ml_config".
 * Peer allowlist controls DISCO probe filtering in wg_mgr.
 *
 * Gated by CONFIG_ML_ENABLE_CONFIG_HTTPD.
 */

#include "sdkconfig.h"

#ifdef CONFIG_ML_ENABLE_CONFIG_HTTPD

#include "ml_config_httpd.h"
#include "ml_at_validate.h"
#include "microlink.h"
#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "driver/temperature_sensor.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_ota_ops.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#ifdef CONFIG_ML_ENABLE_CELLULAR
#include "ml_at_socket.h"
#endif

static const char *TAG = "ml_config";

/* Embedded HTML page */
#include "ml_config_html.h"

/* NVS namespace and keys */
#define NVS_NAMESPACE    "ml_config"
#define NVS_KEY_SETTINGS "settings"
#define NVS_KEY_PEERS    "peers"
#define NVS_KEY_WIFI     "wifi_list"

/* ============================================================================
 * Context Structure
 * ========================================================================== */

struct ml_config_ctx {
    /* NVS handle */
    nvs_handle_t nvs;

    /* Settings (loaded at init, updated via HTTP) */
    ml_config_settings_t settings;

    /* Peer allowlist (read by wg_mgr, written by httpd) */
    SemaphoreHandle_t peer_mutex;
    ml_config_peer_list_t peer_list;
    volatile bool filter_enabled;

    /* WiFi multi-SSID list */
    ml_config_wifi_list_t wifi_list;

    /* Temperature sensor */
    temperature_sensor_handle_t temp_sensor;

    /* HTTP server */
    httpd_handle_t httpd;

    /* Backpointer */
    microlink_t *ml;
};

/* ============================================================================
 * NVS Load/Save
 * ========================================================================== */

static void config_save_peers(ml_config_ctx_t *ctx);  /* forward decl for migration */

/* Fields that end up in modem AT commands (APN, PIN, PPP credentials) or in
 * the control-plane connection / AT DNS lookup (ctrl_host) must never hold
 * '"', CR/LF or other characters outside their grammar. These checks are
 * shared by the web API (reject with 400) and the NVS loaders (drop the
 * value, fall back to Kconfig). Returns NULL if valid, else a message. */
#define FIELD_MAX(f) (sizeof(((ml_config_settings_t *)0)->f) - 1)

static const char *check_cellular_apn(const char *v) {
    return ml_at_param_valid(ML_AT_PARAM_APN, v, FIELD_MAX(cellular_apn)) ? NULL :
        "cellular_apn: letters, digits, '-' and '.' only (max 31)";
}
static const char *check_ppp_user(const char *v) {
    return ml_at_param_valid(ML_AT_PARAM_CREDENTIAL, v, FIELD_MAX(ppp_user)) ? NULL :
        "ppp_user: printable ASCII without '\"' or '\\' (max 31)";
}
static const char *check_ppp_pass(const char *v) {
    return ml_at_param_valid(ML_AT_PARAM_CREDENTIAL, v, FIELD_MAX(ppp_pass)) ? NULL :
        "ppp_pass: printable ASCII without '\"' or '\\' (max 31)";
}
static const char *check_ctrl_host(const char *v) {
    return (v[0] == '\0' || ml_at_param_valid(ML_AT_PARAM_HOSTNAME, v, FIELD_MAX(ctrl_host))) ? NULL :
        "ctrl_host: host name of letters, digits, '-' and '.' (max 63)";
}

/* NVS blobs from older firmware (or corrupt ones) are not guaranteed to be
 * NUL-terminated: force a terminator on every string field after loading,
 * before anything prints or copies them. */
#define TERMINATE(field) ((field)[sizeof(field) - 1] = '\0')

static void terminate_settings_strings(ml_config_settings_t *st) {
    TERMINATE(st->wifi_ssid);
    TERMINATE(st->wifi_pass);
    TERMINATE(st->auth_key);
    TERMINATE(st->device_prefix);
    TERMINATE(st->cellular_apn);
    TERMINATE(st->cellular_sim_pin);
    TERMINATE(st->ctrl_host);
    TERMINATE(st->device_name_full);
    TERMINATE(st->ppp_user);
    TERMINATE(st->ppp_pass);
}

static void terminate_wifi_list_strings(ml_config_wifi_list_t *list) {
    for (int i = 0; i < ML_CONFIG_MAX_WIFI_ENTRIES; i++) {
        TERMINATE(list->entries[i].ssid);
        TERMINATE(list->entries[i].pass);
    }
}

static void terminate_peer_labels(ml_config_peer_list_t *list) {
    for (int i = 0; i < ML_CONFIG_MAX_ALLOWED_PEERS; i++) {
        TERMINATE(list->entries[i].label);
    }
}

/* Settings blobs from older firmware were stored without validation:
 * clear any invalid field. */
static void config_sanitize_settings(ml_config_settings_t *st) {
    #define SANITIZE(field, check) do { \
        (field)[sizeof(field) - 1] = '\0'; \
        if ((check)(field) != NULL) { \
            ESP_LOGW(TAG, "Ignoring invalid saved %s (re-enter it in the web UI)", #field); \
            memset((field), 0, sizeof(field)); \
        } \
    } while (0)
    SANITIZE(st->cellular_apn, check_cellular_apn);
    /* cellular_sim_pin is no longer used (nothing ever read it): drop any
     * PIN an older firmware stored, so it is wiped on the next save. */
    memset(st->cellular_sim_pin, 0, sizeof(st->cellular_sim_pin));
    SANITIZE(st->ppp_user, check_ppp_user);
    SANITIZE(st->ppp_pass, check_ppp_pass);
    SANITIZE(st->ctrl_host, check_ctrl_host);
    #undef SANITIZE
}

static void config_load_settings(ml_config_ctx_t *ctx) {
    /* Read whatever size blob exists — v1 blobs are smaller than v2 struct */
    memset(&ctx->settings, 0, sizeof(ml_config_settings_t));
    size_t len = sizeof(ml_config_settings_t);
    esp_err_t err = nvs_get_blob(ctx->nvs, NVS_KEY_SETTINGS, &ctx->settings, &len);
    terminate_settings_strings(&ctx->settings);

    if (err == ESP_OK && ctx->settings.version >= 1) {
        /* v1 blob is smaller — v2 fields will be zero (defaults) */
        if (ctx->settings.version < ML_CONFIG_SETTINGS_VERSION) {
            ESP_LOGI(TAG, "Migrating settings v%d -> v%d",
                     ctx->settings.version, ML_CONFIG_SETTINGS_VERSION);
            ctx->settings.version = ML_CONFIG_SETTINGS_VERSION;
            /* Save migrated blob so next boot loads full size */
            nvs_set_blob(ctx->nvs, NVS_KEY_SETTINGS, &ctx->settings,
                         sizeof(ml_config_settings_t));
            nvs_commit(ctx->nvs);
        }
    } else {
        memset(&ctx->settings, 0, sizeof(ctx->settings));
        ctx->settings.version = ML_CONFIG_SETTINGS_VERSION;
        ESP_LOGI(TAG, "No saved settings in NVS");
    }

    /* Seed empty fields from Kconfig compile-time defaults.
     * This ensures the web UI displays sdkconfig values even before
     * the user saves anything via the web interface. */
    #define SEED_STR(field, kconfig) do { \
        if ((field)[0] == '\0' && strlen(kconfig) > 0) { \
            strncpy((field), (kconfig), sizeof(field) - 1); \
        } \
    } while (0)

    SEED_STR(ctx->settings.wifi_ssid,    CONFIG_ML_WIFI_SSID);
    SEED_STR(ctx->settings.wifi_pass,    CONFIG_ML_WIFI_PASSWORD);
    SEED_STR(ctx->settings.auth_key,     CONFIG_ML_TAILSCALE_AUTH_KEY);
    SEED_STR(ctx->settings.device_prefix, CONFIG_ML_DEVICE_NAME);
    if (ctx->settings.priority_peer_ip == 0 && strlen(CONFIG_ML_PRIORITY_PEER_IP) > 0) {
        ctx->settings.priority_peer_ip = microlink_parse_ip(CONFIG_ML_PRIORITY_PEER_IP);
    }

    #undef SEED_STR

    config_sanitize_settings(&ctx->settings);

    ESP_LOGI(TAG, "Settings v%d (wifi=%s, prefix=%s, name=%s, max_peers=%d, ctrl=%s, pip=%s)",
             ctx->settings.version,
             ctx->settings.wifi_ssid[0] ? ctx->settings.wifi_ssid : "(empty)",
             ctx->settings.device_prefix[0] ? ctx->settings.device_prefix : "(empty)",
             ctx->settings.device_name_full[0] ? ctx->settings.device_name_full : "(auto)",
             ctx->settings.max_peers,
             ctx->settings.ctrl_host[0] ? ctx->settings.ctrl_host : "(tailscale)",
             strlen(CONFIG_ML_PRIORITY_PEER_IP) > 0 ? CONFIG_ML_PRIORITY_PEER_IP : "(none)");
}

static void config_save_settings(ml_config_ctx_t *ctx) {
    esp_err_t err = nvs_set_blob(ctx->nvs, NVS_KEY_SETTINGS, &ctx->settings,
                                  sizeof(ml_config_settings_t));
    if (err == ESP_OK) {
        nvs_commit(ctx->nvs);
        ESP_LOGI(TAG, "Settings saved to NVS");
    } else {
        ESP_LOGE(TAG, "Failed to save settings: %s", esp_err_to_name(err));
    }
}

static void config_load_peers(ml_config_ctx_t *ctx) {
    /* First, query the stored blob size without reading */
    size_t stored_len = 0;
    esp_err_t err = nvs_get_blob(ctx->nvs, NVS_KEY_PEERS, NULL, &stored_len);

    if (err == ESP_OK && stored_len > 0) {
        /* Old format used uint8_t count (1 byte), new format uses uint16_t (2 bytes).
         * Detect old format by checking if stored size matches old layout:
         * old = 1 + 28*N, new = 2 + 28*N. If (stored_len - 1) % 28 == 0 and
         * (stored_len - 2) % 28 != 0, it's the old format. */
        bool is_old_format = (stored_len >= 1) &&
                             ((stored_len - 1) % sizeof(ml_config_peer_entry_t) == 0) &&
                             ((stored_len - 2) % sizeof(ml_config_peer_entry_t) != 0);

        if (is_old_format) {
            /* Read old format into temp buffer, migrate to new struct */
            uint8_t *tmp = malloc(stored_len);
            if (tmp) {
                size_t rlen = stored_len;
                err = nvs_get_blob(ctx->nvs, NVS_KEY_PEERS, tmp, &rlen);
                if (err == ESP_OK) {
                    /* uint16_t so the bound check is not "always true" when
                     * the limit exceeds 255 (-Wtype-limits, GCC 15) */
                    uint16_t count = tmp[0];
                    if (count > ML_CONFIG_MAX_ALLOWED_PEERS) count = 0;
                    memset(&ctx->peer_list, 0, sizeof(ctx->peer_list));
                    ctx->peer_list.count = count;
                    if (count > 0) {
                        memcpy(ctx->peer_list.entries, tmp + 1,
                               count * sizeof(ml_config_peer_entry_t));
                    }
                    ESP_LOGI(TAG, "Migrated peer allowlist from v1 (uint8 count=%d)", count);
                    /* Re-save in new format */
                    config_save_peers(ctx);
                }
                free(tmp);
            }
        } else {
            /* New format: blob may be smaller than struct (only used entries stored).
             * Zero the struct first, then read up to stored_len bytes into it. */
            memset(&ctx->peer_list, 0, sizeof(ctx->peer_list));
            size_t len = stored_len;
            if (len > sizeof(ml_config_peer_list_t)) len = sizeof(ml_config_peer_list_t);
            err = nvs_get_blob(ctx->nvs, NVS_KEY_PEERS, &ctx->peer_list, &len);
            if (err != ESP_OK || ctx->peer_list.count > ML_CONFIG_MAX_ALLOWED_PEERS) {
                memset(&ctx->peer_list, 0, sizeof(ctx->peer_list));
            }
        }

        terminate_peer_labels(&ctx->peer_list);
        ctx->filter_enabled = (ctx->peer_list.count > 0);
        ESP_LOGI(TAG, "Peer allowlist loaded: %d peers (filter %s)",
                 ctx->peer_list.count, ctx->filter_enabled ? "ON" : "OFF");
    } else {
        memset(&ctx->peer_list, 0, sizeof(ctx->peer_list));
        ctx->filter_enabled = false;
        ESP_LOGI(TAG, "No saved peer allowlist, filter OFF (all peers allowed)");
    }
}

static void config_save_peers(ml_config_ctx_t *ctx) {
    /* Only write count + actual entries (not the full 512-entry array) to save NVS space.
     * This reduces blob from ~14KB to just count*28+2 bytes. */
    size_t save_len = sizeof(ctx->peer_list.count) +
                      ctx->peer_list.count * sizeof(ml_config_peer_entry_t);
    esp_err_t err = nvs_set_blob(ctx->nvs, NVS_KEY_PEERS, &ctx->peer_list, save_len);
    if (err == ESP_OK) {
        nvs_commit(ctx->nvs);
        ESP_LOGI(TAG, "Peer allowlist saved (%d peers, %d bytes)", ctx->peer_list.count, (int)save_len);
    } else {
        ESP_LOGE(TAG, "Failed to save peers (%d bytes): %s", (int)save_len, esp_err_to_name(err));
    }
}

/* ============================================================================
 * WiFi List NVS Load/Save
 * ========================================================================== */

static void config_load_wifi_list(ml_config_ctx_t *ctx) {
    memset(&ctx->wifi_list, 0, sizeof(ctx->wifi_list));
    ctx->wifi_list.active_idx = 0xFF;

    size_t stored_len = 0;
    esp_err_t err = nvs_get_blob(ctx->nvs, NVS_KEY_WIFI, NULL, &stored_len);
    if (err == ESP_OK && stored_len >= 2) {
        size_t read_len = stored_len;
        if (read_len > sizeof(ml_config_wifi_list_t)) read_len = sizeof(ml_config_wifi_list_t);
        err = nvs_get_blob(ctx->nvs, NVS_KEY_WIFI, &ctx->wifi_list, &read_len);
        if (err != ESP_OK || ctx->wifi_list.count > ML_CONFIG_MAX_WIFI_ENTRIES) {
            memset(&ctx->wifi_list, 0, sizeof(ctx->wifi_list));
            ctx->wifi_list.active_idx = 0xFF;
        }
        terminate_wifi_list_strings(&ctx->wifi_list);
        ESP_LOGI(TAG, "WiFi list loaded: %d entries", ctx->wifi_list.count);
    } else {
        /* No wifi_list key — migrate from settings blob if it has WiFi creds */
        if (ctx->settings.wifi_ssid[0] != '\0') {
            ctx->wifi_list.count = 1;
            ctx->wifi_list.active_idx = 0;
            strncpy(ctx->wifi_list.entries[0].ssid, ctx->settings.wifi_ssid, 32);
            strncpy(ctx->wifi_list.entries[0].pass, ctx->settings.wifi_pass, 64);
            ESP_LOGI(TAG, "WiFi list: migrated from settings (%s)", ctx->settings.wifi_ssid);
        } else {
            ESP_LOGI(TAG, "WiFi list: empty (no saved networks)");
        }
    }
}

static void config_save_wifi_list(ml_config_ctx_t *ctx) {
    /* Variable-size save: header (2 bytes) + count * entry_size */
    size_t save_len = 2 + ctx->wifi_list.count * sizeof(ml_config_wifi_entry_t);
    esp_err_t err = nvs_set_blob(ctx->nvs, NVS_KEY_WIFI, &ctx->wifi_list, save_len);
    if (err == ESP_OK) {
        nvs_commit(ctx->nvs);
        ESP_LOGI(TAG, "WiFi list saved (%d entries, %d bytes)",
                 ctx->wifi_list.count, (int)save_len);
    } else {
        ESP_LOGE(TAG, "Failed to save WiFi list (%d bytes): %s",
                 (int)save_len, esp_err_to_name(err));
    }
}

/* ============================================================================
 * Peer Filter API (thread-safe, called from wg_mgr)
 * ========================================================================== */

bool ml_config_peer_is_allowed(const ml_config_ctx_t *ctx, uint32_t vpn_ip) {
    if (!ctx) return true;

    /* Fast path: filter disabled → allow all */
    if (!ctx->filter_enabled) return true;

    /* Slow path: check allowlist under mutex */
    bool allowed = false;
    ml_config_ctx_t *mctx = (ml_config_ctx_t *)ctx;  /* cast away const for mutex */
    if (xSemaphoreTake(mctx->peer_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        for (int i = 0; i < mctx->peer_list.count; i++) {
            if (mctx->peer_list.entries[i].vpn_ip == vpn_ip) {
                allowed = true;
                break;
            }
        }
        xSemaphoreGive(mctx->peer_mutex);
    } else {
        /* Mutex timeout: fail open */
        allowed = true;
    }
    return allowed;
}

/* ============================================================================
 * Settings Query API
 * ========================================================================== */

const char *ml_config_get_wifi_ssid(const ml_config_ctx_t *ctx) {
    if (!ctx || ctx->settings.wifi_ssid[0] == '\0') return NULL;
    return ctx->settings.wifi_ssid;
}

const char *ml_config_get_wifi_pass(const ml_config_ctx_t *ctx) {
    if (!ctx || ctx->settings.wifi_pass[0] == '\0') return NULL;
    return ctx->settings.wifi_pass;
}

const char *ml_config_get_auth_key(const ml_config_ctx_t *ctx) {
    if (!ctx || ctx->settings.auth_key[0] == '\0') return NULL;
    return ctx->settings.auth_key;
}

const char *ml_config_get_device_prefix(const ml_config_ctx_t *ctx) {
    if (!ctx || ctx->settings.device_prefix[0] == '\0') return NULL;
    return ctx->settings.device_prefix;
}

uint8_t ml_config_get_max_peers(const ml_config_ctx_t *ctx) {
    return ctx ? ctx->settings.max_peers : 0;
}

uint16_t ml_config_get_disco_heartbeat_ms(const ml_config_ctx_t *ctx) {
    return ctx ? ctx->settings.disco_heartbeat_ms : 0;
}

uint32_t ml_config_get_priority_peer_ip(const ml_config_ctx_t *ctx) {
    return ctx ? ctx->settings.priority_peer_ip : 0;
}

const char *ml_config_get_ctrl_host(const ml_config_ctx_t *ctx) {
    if (!ctx || ctx->settings.ctrl_host[0] == '\0') return NULL;
    if (check_ctrl_host(ctx->settings.ctrl_host) != NULL) return NULL;
    return ctx->settings.ctrl_host;
}

uint8_t ml_config_get_debug_flags(const ml_config_ctx_t *ctx) {
    return ctx ? ctx->settings.debug_flags : 0;
}

const char *ml_config_get_device_name_full(const ml_config_ctx_t *ctx) {
    if (!ctx || ctx->settings.device_name_full[0] == '\0') return NULL;
    return ctx->settings.device_name_full;
}

/* ============================================================================
 * Access control
 *
 * The config server can change the auth key, WiFi list, APN credentials and
 * control host, so every endpoint requires:
 *   1. the request arrived on an allowed address: the device's own tailnet
 *      (VPN) IP, plus the WiFi station / Ethernet address with
 *      CONFIG_ML_CONFIG_HTTPD_ALLOW_LAN. Never the cellular carrier-facing
 *      (PPP) address.
 *   2. HTTP Basic auth with the admin password (CONFIG_ML_CONFIG_HTTPD_PASSWORD,
 *      or a random one generated on first start, stored in NVS and printed
 *      once on the serial console).
 *   3. a Host header that is an IP literal naming the local address the
 *      request arrived on (blocks DNS rebinding).
 *   4. for state-changing requests, Content-Type: application/json
 *      (cross-site pages can't send it without a CORS preflight, which this
 *      server never approves -> blocks CSRF).
 * ========================================================================== */
#include "mbedtls/base64.h"
#include "lwip/sockets.h"
#include "esp_random.h"

#define HTTP_PW_KEY      "http_pw"
#define HTTP_PW_MAXLEN   64

static char s_http_pw[HTTP_PW_MAXLEN + 1];

static void http_pw_init(void) {
#ifdef CONFIG_ML_CONFIG_HTTPD_PASSWORD
    const char *cfg = CONFIG_ML_CONFIG_HTTPD_PASSWORD;
#else
    const char *cfg = "";
#endif
    if (cfg[0] != '\0') {
        strlcpy(s_http_pw, cfg, sizeof(s_http_pw));
        return;
    }
    nvs_handle_t h;
    size_t len = sizeof(s_http_pw);
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        if (nvs_get_str(h, HTTP_PW_KEY, s_http_pw, &len) != ESP_OK || s_http_pw[0] == '\0') {
            static const char alphabet[] = "abcdefghjkmnpqrstuvwxyzACDEFGHJKLMNPQRTUVWXY34679";
            for (int i = 0; i < 16; i++) {
                s_http_pw[i] = alphabet[esp_random() % (sizeof(alphabet) - 1)];
            }
            s_http_pw[16] = '\0';
            nvs_set_str(h, HTTP_PW_KEY, s_http_pw);
            nvs_commit(h);
            ESP_LOGW(TAG, "Config UI password generated (user 'admin'): %s", s_http_pw);
        }
        nvs_close(h);
    }
    if (s_http_pw[0] == '\0') {
        /* NVS unavailable: fail closed with an unguessable password. */
        for (int i = 0; i < 32; i++) s_http_pw[i] = 'a' + (esp_random() % 26);
        s_http_pw[32] = '\0';
        ESP_LOGE(TAG, "Config UI: could not store a password; UI is locked");
    }
}

static bool ct_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    unsigned char diff = (unsigned char)(la != lb);
    for (size_t i = 0; i < la; i++) {
        diff |= (unsigned char)(a[i] ^ b[i % (lb ? lb : 1)]);
    }
    return diff == 0;
}

/* The IPv4 address (host byte order) the request arrived on.
 *
 * With CONFIG_LWIP_IPV6 (the ESP-IDF default) esp_http_server listens on an
 * AF_INET6 socket bound to in6addr_any, and lwIP reports connections that
 * came in over IPv4 as IPv4-mapped IPv6 addresses (::ffff:a.b.c.d). Those
 * are unwrapped here. Native IPv6 is not accepted: MicroLink only assigns
 * the device an IPv4 tailnet address (no fd7a:115c:a1e0::/48 address is
 * configured on the WireGuard netif), so a native IPv6 connection can only
 * have come in over a LAN or carrier interface. */
static bool request_local_ipv4(httpd_req_t *req, uint32_t *ip_out) {
    int fd = httpd_req_to_sockfd(req);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0) {
        return false;
    }
    if (ss.ss_family == AF_INET) {
        *ip_out = ntohl(((struct sockaddr_in *)&ss)->sin_addr.s_addr);
        return true;
    }
#if LWIP_IPV6
    if (ss.ss_family == AF_INET6) {
        const uint8_t *a = (const uint8_t *)&((struct sockaddr_in6 *)&ss)->sin6_addr;
        static const uint8_t v4mapped_prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        if (memcmp(a, v4mapped_prefix, sizeof(v4mapped_prefix)) != 0) {
            return false;
        }
        *ip_out = ((uint32_t)a[12] << 24) | ((uint32_t)a[13] << 16) |
                  ((uint32_t)a[14] << 8) | (uint32_t)a[15];
        return true;
    }
#endif
    return false;
}

#if CONFIG_ML_CONFIG_HTTPD_ALLOW_LAN
/* esp_netif_find_if() predicate (runs in the lwIP context): a WiFi station
 * or Ethernet interface whose own address is *arg (network byte order).
 * The PPP (cellular carrier) interface never matches. */
static bool lan_netif_has_ip(esp_netif_t *netif, void *arg) {
    const uint32_t want = *(const uint32_t *)arg;
    if (esp_netif_get_flags(netif) & ESP_NETIF_FLAG_IS_PPP) return false;
    const char *key = esp_netif_get_ifkey(netif);
    const char *desc = esp_netif_get_desc(netif);
    bool lan = (key && (strncmp(key, "WIFI_STA", 8) == 0 || strncmp(key, "ETH", 3) == 0)) ||
               (desc && (strcmp(desc, "sta") == 0 || strncmp(desc, "eth", 3) == 0));
    if (!lan || !esp_netif_is_netif_up(netif)) return false;
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(netif, &info) != ESP_OK) return false;
    return info.ip.addr != 0 && info.ip.addr == want;
}
#endif

/* The request must have arrived on the device's own tailnet address (the
 * VPN IP assigned by the control plane) or, with ALLOW_LAN, on the WiFi
 * station / Ethernet interface's own address. Address ranges are not used:
 * 100.64.0.0/10 is also carrier-grade NAT space and 10/8 is a common
 * carrier PPP range, so a range check would serve the UI on the cellular
 * carrier side. @p ml may be NULL (MicroLink stopped: no tailnet address).
 * On success *ip_out is the local IPv4 address (host byte order). */
static bool local_addr_allowed(httpd_req_t *req, const microlink_t *ml, uint32_t *ip_out) {
    uint32_t ip;
    if (!request_local_ipv4(req, &ip) || ip == 0) {
        return false;
    }
    *ip_out = ip;
    uint32_t vpn_ip = ml ? microlink_get_vpn_ip(ml) : 0;
    if (vpn_ip != 0 && ip == vpn_ip) {
        return true;
    }
#if CONFIG_ML_CONFIG_HTTPD_ALLOW_LAN
    uint32_t ip_be = htonl(ip);
    return esp_netif_find_if(lan_netif_has_ip, &ip_be) != NULL;
#else
    return false;
#endif
}

/* Optional ":port" suffix of a Host header: 1-5 digits, <= 65535. */
static bool host_port_ok(const char *p) {
    if (!p) return true;
    unsigned long v = 0;
    int n = 0;
    for (; *p; p++, n++) {
        if (*p < '0' || *p > '9' || n >= 5) return false;
        v = v * 10 + (unsigned long)(*p - '0');
    }
    return n > 0 && v <= 65535;
}

/* DNS-rebinding defence: the Host header must be an IP literal (IPv4, or
 * "[...]" IPv6), with an optional port, naming the address the request
 * arrived on (@p local_ip, host byte order). A character-class check is
 * not enough: names such as "deadbeef.cafe" are made of hex digits only. */
static bool host_is_local_ip_literal(httpd_req_t *req, uint32_t local_ip) {
    char host[64];
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK) {
        return false;
    }
    if (host[0] == '[') {
#if LWIP_IPV6
        char *close = strchr(host, ']');
        if (!close) return false;
        *close = '\0';
        if (close[1] != '\0' && close[1] != ':') return false;
        if (!host_port_ok(close[1] == ':' ? close + 2 : NULL)) return false;
        struct in6_addr a6;
        if (inet_pton(AF_INET6, host + 1, &a6) != 1) return false;
        /* Only an IPv4-mapped form of the local address can match */
        static const uint8_t v4mapped_prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        const uint8_t *b6 = a6.un.u8_addr;
        if (memcmp(b6, v4mapped_prefix, sizeof(v4mapped_prefix)) != 0) return false;
        uint32_t ip = ((uint32_t)b6[12] << 24) | ((uint32_t)b6[13] << 16) |
                      ((uint32_t)b6[14] << 8) | (uint32_t)b6[15];
        return ip == local_ip;
#else
        return false;
#endif
    }
    char *colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        if (!host_port_ok(colon + 1)) return false;
    }
    struct in_addr a4;
    if (inet_pton(AF_INET, host, &a4) != 1) return false;
    return ntohl(a4.s_addr) == local_ip;
}

static bool basic_auth_ok(httpd_req_t *req) {
    char hdr[160];
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) != ESP_OK ||
        strncmp(hdr, "Basic ", 6) != 0) {
        return false;
    }
    unsigned char dec[128];
    size_t dlen = 0;
    if (mbedtls_base64_decode(dec, sizeof(dec) - 1, &dlen,
                              (const unsigned char *)hdr + 6, strlen(hdr + 6)) != 0) {
        return false;
    }
    dec[dlen] = '\0';
    char *colon = strchr((char *)dec, ':');
    if (!colon) return false;
    bool ok = ct_equal(colon + 1, s_http_pw);
    memset(dec, 0, sizeof(dec));
    return ok;
}

/* Returns true if the request may proceed; otherwise a response was sent. */
/* required_ct: Content-Type a state-changing request must carry (one that
 * a cross-site page cannot send without a CORS preflight), NULL for reads. */
static bool http_guard_ct(httpd_req_t *req, const char *required_ct) {
    const ml_config_ctx_t *ctx = (const ml_config_ctx_t *)req->user_ctx;
    uint32_t local_ip;
    if (!local_addr_allowed(req, ctx->ml, &local_ip)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Not available on this interface");
        return false;
    }
    if (!host_is_local_ip_literal(req, local_ip)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Use the device IP address");
        return false;
    }
    if (!basic_auth_ok(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"MicroLink\", charset=\"UTF-8\"");
        httpd_resp_sendstr(req, "Authentication required");
        return false;
    }
    if (required_ct) {
        char ct[48];
        if (httpd_req_get_hdr_value_str(req, "Content-Type", ct, sizeof(ct)) != ESP_OK ||
            strncmp(ct, required_ct, strlen(required_ct)) != 0) {
            char msg[64];
            snprintf(msg, sizeof(msg), "Content-Type must be %s", required_ct);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, msg);
            return false;
        }
    }
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return true;
}

static bool http_guard(httpd_req_t *req, bool mutating) {
    return http_guard_ct(req, mutating ? "application/json" : NULL);
}

/* ============================================================================
 * HTTP Handlers
 * ========================================================================== */

/* Helper: send JSON response */
static esp_err_t send_json(httpd_req_t *req, cJSON *json) {
    char *str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!str) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, str);
    free(str);
    return ESP_OK;
}

/* Helper: read POST body into buffer */
static char *read_post_body(httpd_req_t *req) {
    int content_len = req->content_len;
    if (content_len <= 0 || content_len > 4096) {
        return NULL;
    }
    char *buf = malloc(content_len + 1);
    if (!buf) return NULL;

    int received = 0;
    while (received < content_len) {
        int ret = httpd_req_recv(req, buf + received, content_len - received);
        if (ret <= 0) {
            free(buf);
            return NULL;
        }
        received += ret;
    }
    buf[content_len] = '\0';
    return buf;
}

/* Transport MicroLink's traffic uses: "cellular" over the AT socket bridge
 * or when the PPP netif is the default interface, else "wifi". (Checking
 * only the AT bridge reported "wifi" while on cellular PPP.) */
static const char *active_connection(void) {
#ifdef CONFIG_ML_ENABLE_CELLULAR
    if (ml_at_socket_is_ready()) return "cellular";
#endif
    esp_netif_t *def = esp_netif_get_default_netif();
    if (def && (esp_netif_get_flags(def) & ESP_NETIF_FLAG_IS_PPP)) return "cellular";
    return "wifi";
}

/* GET / — serve HTML config page */
static esp_err_t handler_root(httpd_req_t *req) {
    if (!http_guard(req, false)) return ESP_OK;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr(req, CONFIG_PAGE_HTML);
    return ESP_OK;
}

/* GET /api/status */
static esp_err_t handler_status(httpd_req_t *req) {
    if (!http_guard(req, false)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;
    microlink_t *ml = ctx->ml;

    cJSON *json = cJSON_CreateObject();
    if (!json) return ESP_FAIL;

    /* Firmware identity, so an update can be checked from outside
     * (tools/ml_ota.py) */
    const esp_app_desc_t *app = esp_app_get_description();
    cJSON_AddStringToObject(json, "fw_version", app->version);
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running) cJSON_AddStringToObject(json, "fw_partition", running->label);

    char ip_buf[16] = "0.0.0.0";
    if (ml) {
        uint32_t vpn_ip = microlink_get_vpn_ip(ml);
        if (vpn_ip) microlink_ip_to_str(vpn_ip, ip_buf);
        cJSON_AddStringToObject(json, "vpn_ip", ip_buf);

        static const char *const states[] = {"IDLE", "WIFI_WAIT", "CONNECTING", "REGISTERING",
                                             "CONNECTED", "RECONNECTING", "ERROR",
                                             "AUTH_FAILED", "NEEDS_LOGIN"};
        int s = microlink_get_state(ml);
        int nstates = (int)(sizeof(states) / sizeof(states[0]));
        cJSON_AddStringToObject(json, "state", (s >= 0 && s < nstates) ? states[s] : "UNKNOWN");
        cJSON_AddNumberToObject(json, "peer_count", microlink_get_peer_count(ml));
        cJSON_AddStringToObject(json, "hostname", ml->config.device_name ? ml->config.device_name : "");
    }

    cJSON_AddNumberToObject(json, "free_heap", esp_get_free_heap_size());
    cJSON_AddNumberToObject(json, "free_psram",
        heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    cJSON_AddBoolToObject(json, "filter_enabled", ctx->filter_enabled);

    cJSON_AddStringToObject(json, "connection", active_connection());

    return send_json(req, json);
}

/* GET /api/settings */
static esp_err_t handler_get_settings(httpd_req_t *req) {
    if (!http_guard(req, false)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;

    cJSON *json = cJSON_CreateObject();
    if (!json) return ESP_FAIL;

    cJSON_AddStringToObject(json, "wifi_ssid", ctx->settings.wifi_ssid);
    /* Don't expose password in plain text — show masked */
    cJSON_AddStringToObject(json, "wifi_pass",
        ctx->settings.wifi_pass[0] ? "********" : "");
    cJSON_AddStringToObject(json, "auth_key",
        ctx->settings.auth_key[0] ? "********" : "");
    cJSON_AddStringToObject(json, "device_prefix", ctx->settings.device_prefix);
    cJSON_AddStringToObject(json, "cellular_apn", ctx->settings.cellular_apn);
    cJSON_AddStringToObject(json, "ppp_user", ctx->settings.ppp_user);
    cJSON_AddStringToObject(json, "ppp_pass",
        ctx->settings.ppp_pass[0] ? "********" : "");

    /* v2 fields */
    cJSON_AddNumberToObject(json, "max_peers", ctx->settings.max_peers);
    cJSON_AddNumberToObject(json, "disco_heartbeat_ms", ctx->settings.disco_heartbeat_ms);
    char pip_str[16] = "";
    if (ctx->settings.priority_peer_ip) {
        microlink_ip_to_str(ctx->settings.priority_peer_ip, pip_str);
    }
    cJSON_AddStringToObject(json, "priority_peer_ip", pip_str);
    cJSON_AddStringToObject(json, "ctrl_host", ctx->settings.ctrl_host);
    cJSON_AddNumberToObject(json, "debug_flags", ctx->settings.debug_flags);
    cJSON_AddStringToObject(json, "device_name_full", ctx->settings.device_name_full);

    return send_json(req, json);
}

/* POST /api/settings */
static esp_err_t handler_post_settings(httpd_req_t *req) {
    if (!http_guard(req, true)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;

    char *body = read_post_body(req);
    if (!body) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
        return ESP_FAIL;
    }

    cJSON *json = cJSON_Parse(body);
    free(body);
    if (!json) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    /* Validate every field that reaches a modem AT command or the control
     * connection BEFORE changing anything, so a rejected request leaves the
     * stored settings untouched. Over-long values are rejected, not
     * truncated. Masked placeholders / empty secrets mean "keep". */
    {
        const cJSON *it;
        const char *bad = NULL;
        #define STR_ITEM(name) (((it = cJSON_GetObjectItem(json, (name))) && cJSON_IsString(it)) \
                                ? it->valuestring : NULL)
        const char *v;
        if (!bad && (v = STR_ITEM("cellular_apn"))) bad = check_cellular_apn(v);
        if (!bad && (v = STR_ITEM("ppp_user"))) bad = check_ppp_user(v);
        if (!bad && (v = STR_ITEM("ppp_pass")) && strcmp(v, "********") != 0) bad = check_ppp_pass(v);
        if (!bad && (v = STR_ITEM("ctrl_host"))) bad = check_ctrl_host(v);
        #undef STR_ITEM
        if (bad) {
            cJSON_Delete(json);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, bad);
            return ESP_FAIL;
        }
    }

    /* Helper macro: clear field, copy new value, ensure null termination */
    #define COPY_STR_FIELD(field, val) do { \
        memset((field), 0, sizeof(field)); \
        strncpy((field), (val), sizeof(field) - 1); \
    } while(0)

    /* Update only provided fields (don't clear fields not in the request) */
    cJSON *item;
    if ((item = cJSON_GetObjectItem(json, "wifi_ssid")) && cJSON_IsString(item)) {
        COPY_STR_FIELD(ctx->settings.wifi_ssid, item->valuestring);
    }
    /* For secret fields: skip masked placeholders AND empty strings to prevent
     * accidental credential wipe (browsers may send empty password inputs) */
    if ((item = cJSON_GetObjectItem(json, "wifi_pass")) && cJSON_IsString(item)) {
        const char *v = item->valuestring;
        if (v[0] != '\0' && strcmp(v, "********") != 0) {
            COPY_STR_FIELD(ctx->settings.wifi_pass, v);
        }
    }
    if ((item = cJSON_GetObjectItem(json, "auth_key")) && cJSON_IsString(item)) {
        const char *v = item->valuestring;
        if (v[0] != '\0' && strcmp(v, "********") != 0) {
            COPY_STR_FIELD(ctx->settings.auth_key, v);
        }
    }
    if ((item = cJSON_GetObjectItem(json, "device_prefix")) && cJSON_IsString(item)) {
        COPY_STR_FIELD(ctx->settings.device_prefix, item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "cellular_apn")) && cJSON_IsString(item)) {
        COPY_STR_FIELD(ctx->settings.cellular_apn, item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "ppp_user")) && cJSON_IsString(item)) {
        COPY_STR_FIELD(ctx->settings.ppp_user, item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "ppp_pass")) && cJSON_IsString(item)) {
        const char *v = item->valuestring;
        if (v[0] != '\0' && strcmp(v, "********") != 0) {
            COPY_STR_FIELD(ctx->settings.ppp_pass, v);
        }
    }
    /* v2 fields */
    if ((item = cJSON_GetObjectItem(json, "max_peers")) && cJSON_IsNumber(item)) {
        int v = (int)item->valuedouble;
        ctx->settings.max_peers = (v >= 0 && v <= 64) ? (uint8_t)v : 0;
    }
    if ((item = cJSON_GetObjectItem(json, "disco_heartbeat_ms")) && cJSON_IsNumber(item)) {
        int v = (int)item->valuedouble;
        ctx->settings.disco_heartbeat_ms = (v >= 0 && v <= 60000) ? (uint16_t)v : 0;
    }
    if ((item = cJSON_GetObjectItem(json, "priority_peer_ip")) && cJSON_IsString(item)) {
        ctx->settings.priority_peer_ip = microlink_parse_ip(item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "ctrl_host")) && cJSON_IsString(item)) {
        COPY_STR_FIELD(ctx->settings.ctrl_host, item->valuestring);
    }
    if ((item = cJSON_GetObjectItem(json, "debug_flags")) && cJSON_IsNumber(item)) {
        ctx->settings.debug_flags = (uint8_t)item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(json, "device_name_full")) && cJSON_IsString(item)) {
        COPY_STR_FIELD(ctx->settings.device_name_full, item->valuestring);
    }
    #undef COPY_STR_FIELD
    cJSON_Delete(json);

    config_save_settings(ctx);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddBoolToObject(resp, "restart_required", true);
    return send_json(req, resp);
}

/* GET /api/peers — all known peers with status */
static esp_err_t handler_get_peers(httpd_req_t *req) {
    if (!http_guard(req, false)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;
    microlink_t *ml = ctx->ml;

    cJSON *json = cJSON_CreateObject();
    if (!json) return ESP_FAIL;
    cJSON *arr = cJSON_AddArrayToObject(json, "peers");

    if (ml && arr) {
        int count = microlink_get_peer_count(ml);
        for (int i = 0; i < count; i++) {
            microlink_peer_info_t info;
            if (microlink_get_peer_info(ml, i, &info) != ESP_OK) continue;
            if (info.vpn_ip == 0) continue;

            cJSON *peer = cJSON_CreateObject();
            if (!peer) continue;
            char ip_str[16];
            microlink_ip_to_str(info.vpn_ip, ip_str);
            cJSON_AddStringToObject(peer, "ip", ip_str);
            cJSON_AddStringToObject(peer, "hostname", info.hostname);
            cJSON_AddBoolToObject(peer, "direct", info.direct_path);
            cJSON_AddBoolToObject(peer, "allowed",
                ml_config_peer_is_allowed(ctx, info.vpn_ip));
            cJSON_AddItemToArray(arr, peer);
        }
    }

    return send_json(req, json);
}

/* GET /api/peers/allowed — current allowlist */
static esp_err_t handler_get_allowed(httpd_req_t *req) {
    if (!http_guard(req, false)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;

    cJSON *json = cJSON_CreateObject();
    if (!json) return ESP_FAIL;
    cJSON_AddBoolToObject(json, "filter_enabled", ctx->filter_enabled);
    cJSON *arr = cJSON_AddArrayToObject(json, "peers");

    if (arr && xSemaphoreTake(ctx->peer_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (int i = 0; i < ctx->peer_list.count; i++) {
            cJSON *entry = cJSON_CreateObject();
            if (!entry) continue;
            char ip_str[16];
            microlink_ip_to_str(ctx->peer_list.entries[i].vpn_ip, ip_str);
            cJSON_AddStringToObject(entry, "ip", ip_str);
            cJSON_AddStringToObject(entry, "label", ctx->peer_list.entries[i].label);
            cJSON_AddItemToArray(arr, entry);
        }
        xSemaphoreGive(ctx->peer_mutex);
    }

    return send_json(req, json);
}

/* POST /api/peers/allowed — replace allowlist */
static esp_err_t handler_post_allowed(httpd_req_t *req) {
    if (!http_guard(req, true)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;

    char *body = read_post_body(req);
    if (!body) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
        return ESP_FAIL;
    }

    cJSON *json = cJSON_Parse(body);
    free(body);
    if (!json) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *peers = cJSON_GetObjectItem(json, "peers");
    if (!peers || !cJSON_IsArray(peers)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing peers array");
        return ESP_FAIL;
    }

    if (xSemaphoreTake(ctx->peer_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        ctx->peer_list.count = 0;
        int arr_size = cJSON_GetArraySize(peers);
        for (int i = 0; i < arr_size && i < ML_CONFIG_MAX_ALLOWED_PEERS; i++) {
            cJSON *entry = cJSON_GetArrayItem(peers, i);
            cJSON *ip = cJSON_GetObjectItem(entry, "ip");
            cJSON *label = cJSON_GetObjectItem(entry, "label");
            if (!ip || !cJSON_IsString(ip)) continue;

            uint32_t vpn_ip = microlink_parse_ip(ip->valuestring);
            if (vpn_ip == 0) continue;

            ml_config_peer_entry_t *e = &ctx->peer_list.entries[ctx->peer_list.count];
            e->vpn_ip = vpn_ip;
            memset(e->label, 0, sizeof(e->label));
            if (label && cJSON_IsString(label)) {
                strncpy(e->label, label->valuestring, sizeof(e->label) - 1);
            }
            ctx->peer_list.count++;
        }
        ctx->filter_enabled = (ctx->peer_list.count > 0);
        xSemaphoreGive(ctx->peer_mutex);
    }
    cJSON_Delete(json);

    config_save_peers(ctx);

    ESP_LOGI(TAG, "Allowlist updated: %d peers, filter %s",
             ctx->peer_list.count, ctx->filter_enabled ? "ON" : "OFF");

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddNumberToObject(resp, "count", ctx->peer_list.count);
    cJSON_AddBoolToObject(resp, "filter_enabled", ctx->filter_enabled);
    return send_json(req, resp);
}

/* DELETE /api/peers/allowed — clear allowlist */
static esp_err_t handler_delete_allowed(httpd_req_t *req) {
    if (!http_guard(req, true)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;

    if (xSemaphoreTake(ctx->peer_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        ctx->peer_list.count = 0;
        ctx->filter_enabled = false;
        xSemaphoreGive(ctx->peer_mutex);
    }
    config_save_peers(ctx);

    ESP_LOGI(TAG, "Allowlist cleared, filter OFF (all peers allowed)");

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddBoolToObject(resp, "filter_enabled", false);
    return send_json(req, resp);
}

/* GET /api/monitor — temperature, RSSI, uptime, task stack watermarks */
static esp_err_t handler_monitor(httpd_req_t *req) {
    if (!http_guard(req, false)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;
    microlink_t *ml = ctx->ml;

    cJSON *json = cJSON_CreateObject();
    if (!json) return ESP_FAIL;

    /* Temperature */
    float temp_c = 0;
    if (ctx->temp_sensor) {
        if (temperature_sensor_get_celsius(ctx->temp_sensor, &temp_c) == ESP_OK) {
            cJSON_AddNumberToObject(json, "temp_c", (int)(temp_c * 10) / 10.0);
        } else {
            cJSON_AddNullToObject(json, "temp_c");
        }
    } else {
        cJSON_AddNullToObject(json, "temp_c");
    }

    /* WiFi RSSI */
    int rssi = 0;
    if (esp_wifi_sta_get_rssi(&rssi) == ESP_OK) {
        cJSON_AddNumberToObject(json, "rssi", rssi);
    } else {
        cJSON_AddNullToObject(json, "rssi");
    }

    /* WiFi channel info */
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        cJSON_AddNumberToObject(json, "wifi_channel", ap_info.primary);
        cJSON_AddStringToObject(json, "wifi_ssid", (char *)ap_info.ssid);
    }

    /* Uptime */
    uint64_t uptime_ms = esp_timer_get_time() / 1000;
    cJSON_AddNumberToObject(json, "uptime_s", (double)(uptime_ms / 1000));

    /* Heap */
    cJSON_AddNumberToObject(json, "free_heap", esp_get_free_heap_size());
    cJSON_AddNumberToObject(json, "min_free_heap", esp_get_minimum_free_heap_size());
    cJSON_AddNumberToObject(json, "free_psram",
        heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    /* Task stack watermarks */
    if (ml) {
        cJSON *tasks = cJSON_AddObjectToObject(json, "tasks");
        struct { const char *name; TaskHandle_t handle; } tlist[] = {
            {"net_io",  ml->net_io_task},
            {"derp_tx", ml->derp_tx_task},
            {"coord",   ml->coord_task},
            {"wg_mgr",  ml->wg_mgr_task},
        };
        for (int i = 0; i < 4; i++) {
            if (tlist[i].handle) {
                cJSON *t = cJSON_AddObjectToObject(tasks, tlist[i].name);
                eTaskState st = eTaskGetState(tlist[i].handle);
                const char *sn[] = {"Running","Ready","Blocked","Suspended","Deleted","Invalid"};
                cJSON_AddStringToObject(t, "state", (st <= eInvalid) ? sn[st] : "Unknown");
                cJSON_AddNumberToObject(t, "stack_free",
                    (double)uxTaskGetStackHighWaterMark(tlist[i].handle));
            }
        }

        /* DERP status */
        cJSON_AddBoolToObject(json, "derp_connected", ml->derp.connected);
        cJSON_AddNumberToObject(json, "derp_home_region", ml->derp_home_region);
    }

    /* Connection type */
    cJSON_AddStringToObject(json, "connection", active_connection());

    return send_json(req, json);
}

/* POST /api/restart */
static esp_err_t handler_restart(httpd_req_t *req) {
    if (!http_guard(req, true)) return ESP_OK;
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true,\"restarting\":true}");

    /* Delay to let response complete, then restart */
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;  /* unreachable */
}

#ifdef CONFIG_ML_CONFIG_HTTPD_OTA
/* POST /api/ota: body = an app image (the .bin from the build), sent as
 * application/octet-stream. Written to the next OTA slot, checked by
 * esp_ota_end() (chip, SHA-256 digest, signature with secure boot), made
 * the boot image, then the device restarts into it. With ML_OTA_ROLLBACK
 * the new image is kept only once it reconnects to the tailnet. */
static esp_err_t handler_ota(httpd_req_t *req) {
    if (!http_guard_ct(req, "application/octet-stream")) return ESP_OK;

    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "No OTA slot: flash a partition table with two OTA app partitions");
        return ESP_OK;
    }
    size_t total = req->content_len;
    if (total == 0 || total > part->size) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Image is empty or larger than the OTA slot");
        return ESP_OK;
    }

    esp_ota_handle_t ota = 0;
    esp_err_t err = esp_ota_begin(part, OTA_WITH_SEQUENTIAL_WRITES, &ota);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA begin failed: %s", esp_err_to_name(err));
        httpd_resp_send_500(req);
        return ESP_OK;
    }
    ESP_LOGW(TAG, "Firmware upload started: %u bytes to %s", (unsigned)total, part->label);

    char *buf = malloc(4096);
    size_t got = 0;
    int timeouts = 0;
    err = buf ? ESP_OK : ESP_ERR_NO_MEM;
    while (err == ESP_OK && got < total) {
        size_t want = total - got < 4096 ? total - got : 4096;
        int n = httpd_req_recv(req, buf, want);
        if (n == HTTPD_SOCK_ERR_TIMEOUT && ++timeouts <= 6) continue;
        if (n <= 0) {
            err = ESP_FAIL;
            break;
        }
        timeouts = 0;
        err = esp_ota_write(ota, buf, (size_t)n);
        got += (size_t)n;
    }
    free(buf);
    if (err != ESP_OK) {
        esp_ota_abort(ota);
        ESP_LOGE(TAG, "Firmware upload failed after %u/%u bytes: %s",
                 (unsigned)got, (unsigned)total, esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Upload failed or not an app image");
        return ESP_OK;
    }
    err = esp_ota_end(ota);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Uploaded image rejected: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Image rejected (corrupt, wrong chip or bad signature)");
        return ESP_OK;
    }
    err = esp_ota_set_boot_partition(part);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Could not select the new image: %s", esp_err_to_name(err));
        httpd_resp_send_500(req);
        return ESP_OK;
    }

    ESP_LOGW(TAG, "Firmware update written to %s; restarting", part->label);
    char resp[96];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"partition\":\"%s\",\"bytes\":%u,\"restarting\":true}",
             part->label, (unsigned)total);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;  /* unreachable */
}
#endif

/* ============================================================================
 * WiFi List HTTP Handlers
 * ========================================================================== */

/* GET /api/wifi — return WiFi list with masked passwords */
static esp_err_t handler_get_wifi(httpd_req_t *req) {
    if (!http_guard(req, false)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;

    cJSON *json = cJSON_CreateObject();
    if (!json) return ESP_FAIL;
    cJSON *arr = cJSON_AddArrayToObject(json, "networks");

    for (int i = 0; i < ctx->wifi_list.count && i < ML_CONFIG_MAX_WIFI_ENTRIES; i++) {
        cJSON *entry = cJSON_CreateObject();
        if (!entry) continue;
        cJSON_AddStringToObject(entry, "ssid", ctx->wifi_list.entries[i].ssid);
        cJSON_AddStringToObject(entry, "pass",
            ctx->wifi_list.entries[i].pass[0] ? "********" : "");
        cJSON_AddItemToArray(arr, entry);
    }
    cJSON_AddNumberToObject(json, "active_idx",
        ctx->wifi_list.active_idx == 0xFF ? -1 : ctx->wifi_list.active_idx);

    return send_json(req, json);
}

/* POST /api/wifi — replace entire WiFi list */
static esp_err_t handler_post_wifi(httpd_req_t *req) {
    if (!http_guard(req, true)) return ESP_OK;
    ml_config_ctx_t *ctx = (ml_config_ctx_t *)req->user_ctx;

    char *body = read_post_body(req);
    if (!body) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
        return ESP_FAIL;
    }

    cJSON *json = cJSON_Parse(body);
    free(body);
    if (!json) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *networks = cJSON_GetObjectItem(json, "networks");
    if (!networks || !cJSON_IsArray(networks)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing networks array");
        return ESP_FAIL;
    }

    /* Save old list so we can resolve masked passwords */
    ml_config_wifi_list_t old_list;
    memcpy(&old_list, &ctx->wifi_list, sizeof(old_list));

    /* Build new list */
    memset(&ctx->wifi_list, 0, sizeof(ctx->wifi_list));
    ctx->wifi_list.active_idx = 0xFF;

    int arr_size = cJSON_GetArraySize(networks);
    for (int i = 0; i < arr_size && i < ML_CONFIG_MAX_WIFI_ENTRIES; i++) {
        cJSON *entry = cJSON_GetArrayItem(networks, i);
        cJSON *ssid = cJSON_GetObjectItem(entry, "ssid");
        cJSON *pass = cJSON_GetObjectItem(entry, "pass");
        if (!ssid || !cJSON_IsString(ssid) || ssid->valuestring[0] == '\0') continue;

        ml_config_wifi_entry_t *e = &ctx->wifi_list.entries[ctx->wifi_list.count];
        memset(e, 0, sizeof(*e));
        strncpy(e->ssid, ssid->valuestring, sizeof(e->ssid) - 1);

        if (pass && cJSON_IsString(pass)) {
            const char *pv = pass->valuestring;
            if (strcmp(pv, "********") == 0) {
                /* Masked: find matching SSID in old list and copy password */
                for (int j = 0; j < old_list.count; j++) {
                    if (strcmp(old_list.entries[j].ssid, e->ssid) == 0) {
                        strncpy(e->pass, old_list.entries[j].pass, sizeof(e->pass) - 1);
                        break;
                    }
                }
            } else if (pv[0] != '\0') {
                strncpy(e->pass, pv, sizeof(e->pass) - 1);
            }
        }
        ctx->wifi_list.count++;
    }
    cJSON_Delete(json);

    /* Update settings blob wifi_ssid/wifi_pass with entry[0] for backwards compat */
    if (ctx->wifi_list.count > 0) {
        memset(ctx->settings.wifi_ssid, 0, sizeof(ctx->settings.wifi_ssid));
        memset(ctx->settings.wifi_pass, 0, sizeof(ctx->settings.wifi_pass));
        strncpy(ctx->settings.wifi_ssid, ctx->wifi_list.entries[0].ssid,
                sizeof(ctx->settings.wifi_ssid) - 1);
        strncpy(ctx->settings.wifi_pass, ctx->wifi_list.entries[0].pass,
                sizeof(ctx->settings.wifi_pass) - 1);
        config_save_settings(ctx);
    }

    config_save_wifi_list(ctx);

    ESP_LOGI(TAG, "WiFi list updated: %d networks", ctx->wifi_list.count);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddNumberToObject(resp, "count", ctx->wifi_list.count);
    cJSON_AddBoolToObject(resp, "restart_required", true);
    return send_json(req, resp);
}

/* ============================================================================
 * WiFi List Public API
 * ========================================================================== */

bool ml_config_get_wifi_list(ml_config_wifi_list_t *list) {
    if (!list) return false;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return false;

    memset(list, 0, sizeof(*list));
    list->active_idx = 0xFF;

    /* Try wifi_list key first */
    size_t stored_len = 0;
    err = nvs_get_blob(nvs, NVS_KEY_WIFI, NULL, &stored_len);
    if (err == ESP_OK && stored_len >= 2) {
        size_t read_len = stored_len;
        if (read_len > sizeof(ml_config_wifi_list_t)) read_len = sizeof(ml_config_wifi_list_t);
        err = nvs_get_blob(nvs, NVS_KEY_WIFI, list, &read_len);
        if (err == ESP_OK && list->count > 0 && list->count <= ML_CONFIG_MAX_WIFI_ENTRIES) {
            terminate_wifi_list_strings(list);
            nvs_close(nvs);
            return true;
        }
        /* Invalid data, fall through */
        memset(list, 0, sizeof(*list));
        list->active_idx = 0xFF;
    }

    /* Fall back to settings blob WiFi (heap-alloc to avoid stack overflow) */
    ml_config_settings_t *settings = heap_caps_malloc(sizeof(*settings), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!settings) { nvs_close(nvs); return false; }
    memset(settings, 0, sizeof(*settings));
    size_t slen = sizeof(*settings);
    err = nvs_get_blob(nvs, NVS_KEY_SETTINGS, settings, &slen);
    nvs_close(nvs);
    terminate_settings_strings(settings);

    if (err == ESP_OK && settings->wifi_ssid[0] != '\0') {
        list->count = 1;
        list->active_idx = 0;
        strncpy(list->entries[0].ssid, settings->wifi_ssid, 32);
        strncpy(list->entries[0].pass, settings->wifi_pass, 64);
        free(settings);
        return true;
    }

    free(settings);
    return false;
}

/* ============================================================================
 * Early Boot WiFi Override (reads NVS without full config init)
 * ========================================================================== */

bool ml_config_get_nvs_wifi(char *ssid, size_t ssid_len,
                             char *pass, size_t pass_len) {
    /* Heap-allocate to avoid stack overflow in app_main (1570+400 bytes) */
    ml_config_wifi_list_t *wlist = heap_caps_malloc(sizeof(*wlist), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (wlist && ml_config_get_wifi_list(wlist) && wlist->count > 0) {
        if (ssid && ssid_len > 0) {
            strncpy(ssid, wlist->entries[0].ssid, ssid_len - 1);
            ssid[ssid_len - 1] = '\0';
        }
        if (pass && pass_len > 0) {
            strncpy(pass, wlist->entries[0].pass, pass_len - 1);
            pass[pass_len - 1] = '\0';
        }
        ESP_LOGI(TAG, "WiFi from wifi_list[0]: %s", wlist->entries[0].ssid);
        free(wlist);
        return true;
    }
    free(wlist);  /* NULL-safe */

    /* Fall back to settings blob */
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return false;

    ml_config_settings_t *settings = heap_caps_malloc(sizeof(*settings), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!settings) { nvs_close(nvs); return false; }
    memset(settings, 0, sizeof(*settings));
    size_t len = sizeof(*settings);
    err = nvs_get_blob(nvs, NVS_KEY_SETTINGS, settings, &len);
    nvs_close(nvs);
    terminate_settings_strings(settings);

    if (err != ESP_OK || len < 1 || settings->version < 1 || settings->wifi_ssid[0] == '\0') {
        free(settings);
        return false;
    }

    if (ssid && ssid_len > 0) {
        strncpy(ssid, settings->wifi_ssid, ssid_len - 1);
        ssid[ssid_len - 1] = '\0';
    }
    if (pass && pass_len > 0) {
        strncpy(pass, settings->wifi_pass, pass_len - 1);
        pass[pass_len - 1] = '\0';
    }

    ESP_LOGI(TAG, "WiFi from settings: %s", settings->wifi_ssid);
    free(settings);
    return true;
}

bool ml_config_get_nvs_ppp(char *user, size_t user_len,
                            char *pass, size_t pass_len) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return false;

    ml_config_settings_t *settings = heap_caps_malloc(sizeof(*settings), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!settings) { nvs_close(nvs); return false; }
    memset(settings, 0, sizeof(*settings));
    size_t len = sizeof(*settings);
    err = nvs_get_blob(nvs, NVS_KEY_SETTINGS, settings, &len);
    nvs_close(nvs);
    terminate_settings_strings(settings);

    if (err != ESP_OK || len < 1 || settings->version < 3 || settings->ppp_user[0] == '\0') {
        free(settings);
        return false;
    }
    settings->ppp_user[sizeof(settings->ppp_user) - 1] = '\0';
    settings->ppp_pass[sizeof(settings->ppp_pass) - 1] = '\0';
    if (check_ppp_user(settings->ppp_user) || check_ppp_pass(settings->ppp_pass)) {
        ESP_LOGW(TAG, "Ignoring invalid PPP credentials in NVS");
        ml_at_secure_zero(settings, sizeof(*settings));
        free(settings);
        return false;
    }

    if (user && user_len > 0) {
        strncpy(user, settings->ppp_user, user_len - 1);
        user[user_len - 1] = '\0';
    }
    if (pass && pass_len > 0) {
        strncpy(pass, settings->ppp_pass, pass_len - 1);
        pass[pass_len - 1] = '\0';
    }

    ESP_LOGI(TAG, "PPP credentials from NVS");
    ml_at_secure_zero(settings, sizeof(*settings));
    free(settings);
    return true;
}

bool ml_config_get_nvs_apn(char *apn, size_t apn_len) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return false;

    ml_config_settings_t *settings = heap_caps_malloc(sizeof(*settings), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!settings) { nvs_close(nvs); return false; }
    memset(settings, 0, sizeof(*settings));
    size_t len = sizeof(*settings);
    err = nvs_get_blob(nvs, NVS_KEY_SETTINGS, settings, &len);
    nvs_close(nvs);
    terminate_settings_strings(settings);

    if (err != ESP_OK || len < 1 || settings->cellular_apn[0] == '\0') {
        free(settings);
        return false;
    }
    settings->cellular_apn[sizeof(settings->cellular_apn) - 1] = '\0';
    if (check_cellular_apn(settings->cellular_apn)) {
        ESP_LOGW(TAG, "Ignoring invalid APN in NVS");
        free(settings);
        return false;
    }

    if (apn && apn_len > 0) {
        strncpy(apn, settings->cellular_apn, apn_len - 1);
        apn[apn_len - 1] = '\0';
    }

    ESP_LOGI(TAG, "APN from NVS: %s", settings->cellular_apn);
    free(settings);
    return true;
}

/* ============================================================================
 * Lifecycle
 * ========================================================================== */

ml_config_ctx_t *ml_config_httpd_init(void) {
    ml_config_ctx_t *ctx = calloc(1, sizeof(ml_config_ctx_t));
    if (!ctx) return NULL;

    ctx->peer_mutex = xSemaphoreCreateMutex();
    if (!ctx->peer_mutex) {
        free(ctx);
        return NULL;
    }

    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &ctx->nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS namespace '%s': %s",
                 NVS_NAMESPACE, esp_err_to_name(err));
        vSemaphoreDelete(ctx->peer_mutex);
        free(ctx);
        return NULL;
    }

    config_load_settings(ctx);
    config_load_peers(ctx);
    config_load_wifi_list(ctx);

    /* Initialize temperature sensor */
    temperature_sensor_config_t tsens_cfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(10, 80);
    if (temperature_sensor_install(&tsens_cfg, &ctx->temp_sensor) == ESP_OK) {
        temperature_sensor_enable(ctx->temp_sensor);
        ESP_LOGI(TAG, "Temperature sensor initialized");
    } else {
        ctx->temp_sensor = NULL;
        ESP_LOGW(TAG, "Temperature sensor init failed (non-critical)");
    }

    ESP_LOGI(TAG, "Config module initialized");
    return ctx;
}

/* The HTTP server is started once and then kept for the life of the process;
 * microlink_stop()/microlink_destroy() only detach it from the context.
 *
 * Why: on ESP-IDF 5.3 esp_http_server's task ends with
 * vTaskDeleteWithCaps(xTaskGetCurrentTaskHandle()). vTaskDelete() of the
 * calling task never returns, so the stack and TCB that call was meant to
 * free afterwards are leaked: 6144 + sizeof(StaticTask_t) bytes of internal
 * RAM (6492 on the S3) on every httpd_stop(). Stopping and restarting the
 * server with every microlink_stop()/microlink_start() leaked that much per
 * cycle.
 *
 * While no context is attached every URI answers 503. Handlers run with
 * s_attach_lock held, so detaching waits for an in-flight request and the
 * context cannot be freed under it. */
static httpd_handle_t s_httpd;
static ml_config_ctx_t *s_attached;
static SemaphoreHandle_t s_attach_lock;
static StaticSemaphore_t s_attach_lock_buf;

/* Every URI is registered with this handler; user_ctx is the real one. */
static esp_err_t handler_dispatch(httpd_req_t *req) {
    esp_err_t (*real)(httpd_req_t *) = (esp_err_t (*)(httpd_req_t *))req->user_ctx;
    xSemaphoreTake(s_attach_lock, portMAX_DELAY);
    ml_config_ctx_t *ctx = s_attached;
    if (!ctx || !ctx->ml) {
        xSemaphoreGive(s_attach_lock);
        /* Without MicroLink there is no tailnet address, so only a LAN
         * address (ALLOW_LAN) can pass; everyone else gets the same 403
         * as when MicroLink is running. */
        uint32_t local_ip;
        if (!local_addr_allowed(req, NULL, &local_ip)) {
            httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Not available on this interface");
            return ESP_OK;
        }
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_sendstr(req, "MicroLink is not running");
        return ESP_OK;
    }
    req->user_ctx = ctx;  /* per-request field; the handlers read the context from it */
    esp_err_t ret = real(req);
    xSemaphoreGive(s_attach_lock);
    return ret;
}

static esp_err_t config_server_start_once(void) {
    if (s_httpd) return ESP_OK;

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 6144;
    config.max_uri_handlers = 14;
    config.uri_match_fn = httpd_uri_match_wildcard;

    httpd_handle_t h = NULL;
    esp_err_t err = httpd_start(&h, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server: %s", esp_err_to_name(err));
        return err;
    }

    /* Register URI handlers (user_ctx = the real handler, see handler_dispatch) */
    static const struct {
        const char *uri;
        httpd_method_t method;
        esp_err_t (*fn)(httpd_req_t *);
    } routes[] = {
        { "/",                  HTTP_GET,    handler_root },
        { "/api/status",        HTTP_GET,    handler_status },
        { "/api/settings",      HTTP_GET,    handler_get_settings },
        { "/api/settings",      HTTP_POST,   handler_post_settings },
        { "/api/monitor",       HTTP_GET,    handler_monitor },
        { "/api/peers",         HTTP_GET,    handler_get_peers },
        { "/api/peers/allowed", HTTP_GET,    handler_get_allowed },
        { "/api/peers/allowed", HTTP_POST,   handler_post_allowed },
        { "/api/peers/allowed", HTTP_DELETE, handler_delete_allowed },
        { "/api/restart",       HTTP_POST,   handler_restart },
        { "/api/wifi",          HTTP_GET,    handler_get_wifi },
        { "/api/wifi",          HTTP_POST,   handler_post_wifi },
#ifdef CONFIG_ML_CONFIG_HTTPD_OTA
        { "/api/ota",           HTTP_POST,   handler_ota },
#endif
    };

    for (int i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_uri_t u = {
            .uri = routes[i].uri,
            .method = routes[i].method,
            .handler = handler_dispatch,
            .user_ctx = (void *)routes[i].fn,
        };
        httpd_register_uri_handler(h, &u);
    }

    s_httpd = h;
    ESP_LOGI(TAG, "HTTP config server started on port %d", config.server_port);
    return ESP_OK;
}

esp_err_t ml_config_httpd_start(ml_config_ctx_t *ctx, microlink_t *ml) {
    if (!ctx) return ESP_ERR_INVALID_ARG;
    if (!s_attach_lock) {
        s_attach_lock = xSemaphoreCreateMutexStatic(&s_attach_lock_buf);
    }

    http_pw_init();

    esp_err_t err = config_server_start_once();
    if (err != ESP_OK) return err;

    xSemaphoreTake(s_attach_lock, portMAX_DELAY);
    ctx->ml = ml;
    ctx->httpd = s_httpd;
    s_attached = ctx;
    xSemaphoreGive(s_attach_lock);
    return ESP_OK;
}

void ml_config_httpd_stop(ml_config_ctx_t *ctx) {
    if (!ctx || !s_attach_lock) return;
    /* Waits for a request being handled for this context to finish. */
    xSemaphoreTake(s_attach_lock, portMAX_DELAY);
    bool was_attached = (s_attached == ctx);
    if (was_attached) s_attached = NULL;
    ctx->ml = NULL;
    ctx->httpd = NULL;
    xSemaphoreGive(s_attach_lock);
    if (was_attached) {
        ESP_LOGI(TAG, "HTTP config server detached (server kept running)");
    }
}

void ml_config_httpd_deinit(ml_config_ctx_t *ctx) {
    if (!ctx) return;
    ml_config_httpd_stop(ctx);
    if (ctx->temp_sensor) {
        temperature_sensor_disable(ctx->temp_sensor);
        temperature_sensor_uninstall(ctx->temp_sensor);
    }
    if (ctx->nvs) nvs_close(ctx->nvs);
    if (ctx->peer_mutex) vSemaphoreDelete(ctx->peer_mutex);
    free(ctx);
}

#endif /* CONFIG_ML_ENABLE_CONFIG_HTTPD */
