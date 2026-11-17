/**
 * @file microlink.c
 * @brief MicroLink v2 - Public API and Task Orchestration
 *
 * Creates all FreeRTOS tasks, queues, and event groups.
 * Provides the public API that the application calls.
 */

#include "microlink_internal.h"
#include "ml_filter.h"
#include "ml_at_validate.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "cJSON.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include "lwip/sockets.h"

#ifdef CONFIG_ML_ENABLE_CELLULAR
#include "ml_cellular.h"
#endif

static const char *TAG = "microlink";

/* NVS keys */
#define NVS_NAMESPACE       "microlink"
#define NVS_KEY_MACHINE_PRI "machine_pri"
#define NVS_KEY_MACHINE_PUB "machine_pub"
#define NVS_KEY_WG_PRI      "wg_private"
#define NVS_KEY_WG_PUB      "wg_public"
#define NVS_KEY_DISCO_PRI   "disco_pri"
#define NVS_KEY_DISCO_PUB   "disco_pub"

/* X25519 from x25519.h */
#include "x25519.h"

/* ============================================================================
 * Key Management (loaded once at init, read-only after)
 * ========================================================================== */

static void generate_keypair(uint8_t *private_key, uint8_t *public_key) {
    esp_fill_random(private_key, 32);
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    x25519_base(public_key, private_key, 1);
}

static esp_err_t load_or_generate_keys(microlink_t *ml) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NVS open failed (%d), generating ephemeral keys", err);
        generate_keypair(ml->machine_private_key, ml->machine_public_key);
        generate_keypair(ml->wg_private_key, ml->wg_public_key);
        generate_keypair(ml->disco_private_key, ml->disco_public_key);
        return ESP_OK;
    }

    size_t key_len = 32;
    bool need_save = false;

    /* Machine key */
    if (nvs_get_blob(nvs, NVS_KEY_MACHINE_PRI, ml->machine_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->machine_private_key, ml->machine_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new machine key");
    } else {
        key_len = 32;
        nvs_get_blob(nvs, NVS_KEY_MACHINE_PUB, ml->machine_public_key, &key_len);
    }

    /* WireGuard key */
    key_len = 32;
    if (nvs_get_blob(nvs, NVS_KEY_WG_PRI, ml->wg_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->wg_private_key, ml->wg_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new WireGuard key");
    } else {
        key_len = 32;
        nvs_get_blob(nvs, NVS_KEY_WG_PUB, ml->wg_public_key, &key_len);
    }

    /* DISCO key */
    key_len = 32;
    if (nvs_get_blob(nvs, NVS_KEY_DISCO_PRI, ml->disco_private_key, &key_len) != ESP_OK) {
        generate_keypair(ml->disco_private_key, ml->disco_public_key);
        need_save = true;
        ESP_LOGI(TAG, "Generated new DISCO key");
    } else {
        key_len = 32;
        nvs_get_blob(nvs, NVS_KEY_DISCO_PUB, ml->disco_public_key, &key_len);
    }

    if (need_save) {
        nvs_set_blob(nvs, NVS_KEY_MACHINE_PRI, ml->machine_private_key, 32);
        nvs_set_blob(nvs, NVS_KEY_MACHINE_PUB, ml->machine_public_key, 32);
        nvs_set_blob(nvs, NVS_KEY_WG_PRI, ml->wg_private_key, 32);
        nvs_set_blob(nvs, NVS_KEY_WG_PUB, ml->wg_public_key, 32);
        nvs_set_blob(nvs, NVS_KEY_DISCO_PRI, ml->disco_private_key, 32);
        nvs_set_blob(nvs, NVS_KEY_DISCO_PUB, ml->disco_public_key, 32);
        nvs_commit(nvs);
        ESP_LOGI(TAG, "Keys saved to NVS");
    } else {
        ESP_LOGI(TAG, "Keys loaded from NVS");
    }

    nvs_close(nvs);
    return ESP_OK;
}

/* ============================================================================
 * cJSON PSRAM Hooks
 * ========================================================================== */

static void *cjson_psram_malloc(size_t size) {
    return ml_psram_malloc(size);
}

/* ============================================================================
 * Factory Reset
 * ========================================================================== */

esp_err_t microlink_factory_reset(void) {
    esp_err_t err;

    /* Erase key namespace */
    nvs_handle_t nvs;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
        ESP_LOGI(TAG, "Factory reset: keys erased");
    }

    /* Erase runtime settings set via the config UI (auth key, WiFi list,
     * APN/PPP credentials, control host, UI password). These override
     * Kconfig, so leaving them would let planted values survive a reset. */
    err = nvs_open("ml_config", NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
        ESP_LOGI(TAG, "Factory reset: runtime settings erased");
    }

    /* Erase cached peers */
    ml_peer_nvs_init();
    ml_peer_nvs_clear();
    ml_peer_nvs_deinit();

    ESP_LOGI(TAG, "Factory reset complete");
    return ESP_OK;
}

/* ============================================================================
 * Task Lifecycle
 *
 * The four worker tasks (net_io, derp_tx, coord, wg_mgr) hold a raw pointer
 * to the context for their whole life. ml->tasks_alive has one bit per task:
 * microlink_start() sets it before creating the task, and the task clears it
 * in ml_task_exit() as its last access to the context. microlink_stop() waits
 * for the mask to reach zero instead of sleeping a fixed time, and nothing
 * that a task can still reach is freed while its bit is set.
 *
 * A context whose tasks did not exit within CONFIG_ML_STOP_TIMEOUT_MS (a task
 * stuck in getaddrinfo() or a TCP connect, which cannot be interrupted) is
 * not freed by microlink_destroy(); it is parked and released by a later
 * microlink_init()/microlink_destroy() once the task is gone.
 *
 * Approach from fugo101 6a7d8c5 (task-liveness bitmask, orphan parking).
 * ========================================================================== */

#ifndef CONFIG_ML_STOP_TIMEOUT_MS
#define CONFIG_ML_STOP_TIMEOUT_MS 30000
#endif

/* Time the tasks get to notice the shutdown bit on their own before stop
 * shuts down their sockets to unblock reads. */
#define ML_STOP_GRACE_MS    1000
#define ML_JOIN_POLL_MS     20

/* Every bit a FreeRTOS event group can hold (24 with 32-bit ticks). */
#define ML_EVT_ALL_BITS     0x00FFFFFFu

/* Contexts whose free had to be deferred. */
#define ML_MAX_ORPHANS      4
static microlink_t *s_orphans[ML_MAX_ORPHANS];
static portMUX_TYPE s_orphan_mux = portMUX_INITIALIZER_UNLOCKED;

/* Contexts allocated and not yet freed (including parked ones). The peer
 * NVS cache is process-wide and is closed when the last one goes. */
static int s_live_contexts;

uint32_t ml_tasks_alive(const microlink_t *ml) {
    if (!ml) return 0;
    return __atomic_load_n(&ml->tasks_alive, __ATOMIC_ACQUIRE);
}

bool ml_shutdown_requested(const microlink_t *ml) {
    if (!ml || !ml->events) return true;
    return (xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST) != 0;
}

void ml_task_exit(microlink_t *ml, uint32_t task_bit) {
    if (ml) {
        if (task_bit & ML_TASK_BIT_NET_IO)  ml->net_io_task = NULL;
        if (task_bit & ML_TASK_BIT_DERP_TX) ml->derp_tx_task = NULL;
        if (task_bit & ML_TASK_BIT_COORD)   ml->coord_task = NULL;
        if (task_bit & ML_TASK_BIT_WG_MGR)  ml->wg_mgr_task = NULL;
        /* From here on ml may be freed by another task at any moment. */
        __atomic_fetch_and(&ml->tasks_alive, ~task_bit, __ATOMIC_RELEASE);
    }
    vTaskDelete(NULL);
    for (;;) { vTaskDelay(portMAX_DELAY); }  /* not reached */
}

static void ml_describe_tasks(uint32_t mask, char *out, size_t out_len) {
    snprintf(out, out_len, "%s%s%s%s",
             (mask & ML_TASK_BIT_NET_IO)  ? " net_io"  : "",
             (mask & ML_TASK_BIT_DERP_TX) ? " derp_tx" : "",
             (mask & ML_TASK_BIT_COORD)   ? " coord"   : "",
             (mask & ML_TASK_BIT_WG_MGR)  ? " wg_mgr"  : "");
}

/* Wait until every task has exited or timeout_ms passes. Returns the mask of
 * tasks still running. */
static uint32_t ml_join_tasks(const microlink_t *ml, uint32_t timeout_ms) {
    uint32_t waited = 0;
    uint32_t alive;
    while ((alive = ml_tasks_alive(ml)) != 0 && waited < timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(ML_JOIN_POLL_MS));
        waited += ML_JOIN_POLL_MS;
    }
    return alive;
}

/* shutdown() a task's TCP socket so a recv()/send() blocked in it returns at
 * once instead of after its SO_RCVTIMEO (up to 60 s for a MapResponse). The
 * owning task still closes the descriptor itself. AT-bridge descriptors are
 * not lwIP sockets; those tasks are left to their own timeouts. */
static void ml_unblock_socket(int fd) {
    if (fd < 0 || ml_at_socket_is_at_fd(fd)) return;
    shutdown(fd, SHUT_RDWR);
}

/* Free every packet buffer still sitting in the queues. Each item owns heap
 * memory that vQueueDelete()/xQueueReset() would otherwise drop. Precondition:
 * no task is running. */
static void ml_drain_queues(microlink_t *ml) {
    int dropped = 0;
    ml_rx_packet_t pkt;
    QueueHandle_t rxq[] = { ml->disco_rx_queue, ml->wg_rx_queue, ml->stun_rx_queue };
    for (size_t i = 0; i < sizeof(rxq) / sizeof(rxq[0]); i++) {
        if (!rxq[i]) continue;
        while (xQueueReceive(rxq[i], &pkt, 0) == pdTRUE) { free(pkt.data); dropped++; }
    }
    if (ml->derp_tx_queue) {
        ml_derp_tx_item_t item;
        while (xQueueReceive(ml->derp_tx_queue, &item, 0) == pdTRUE) { free(item.data); dropped++; }
    }
    if (ml->peer_update_queue) {
        ml_peer_update_t *upd;
        while (xQueueReceive(ml->peer_update_queue, &upd, 0) == pdTRUE) { free(upd); dropped++; }
    }
    if (ml->coord_cmd_queue) xQueueReset(ml->coord_cmd_queue);
    if (dropped) ESP_LOGI(TAG, "Freed %d queued buffers", dropped);
}

/* Release what one start/stop run owns and reset per-run state so the next
 * microlink_start() begins clean. Precondition: no task is running. */
static void ml_release_run_resources(microlink_t *ml) {
#ifdef CONFIG_ML_ZERO_COPY_WG
    ml_zerocopy_deinit(ml);
#endif
    if (ml->disco_sock4 >= 0) { ml_close_sock(ml->disco_sock4); ml->disco_sock4 = -1; }
    if (ml->disco_sock6 >= 0) { ml_close_sock(ml->disco_sock6); ml->disco_sock6 = -1; }
    if (ml->stun_sock >= 0)   { ml_close_sock(ml->stun_sock);   ml->stun_sock = -1; }
    if (ml->stun_sock6 >= 0)  { ml_close_sock(ml->stun_sock6);  ml->stun_sock6 = -1; }
    /* coord and derp_tx close their own connections on exit (coord_close_conn,
     * ml_derp_disconnect); these only catch a task that never ran. */
    if (ml->coord_sock >= 0)  { ml_close_sock(ml->coord_sock);  ml->coord_sock = -1; }
    if (ml->derp.sockfd >= 0) { ml_derp_disconnect(ml); }

    if (ml->wg_netif) {
        /* wg_mgr removes and frees the netif on exit; if it is still here
         * the tcpip_thread could not be reached, and freeing it now could
         * crash that thread. Leak it rather than risk that. */
        ESP_LOGE(TAG, "WireGuard netif still attached after stop; leaking it");
        ml->wg_netif = NULL;
    }

    ml_drain_queues(ml);

    /* Peer table: wg_peer_index values refer to the WireGuard device that
     * wg_mgr just freed, and wg_mgr only overwrites the table on the next
     * start when the NVS cache is non-empty. */
    memset(ml->peers, 0, sizeof(ml->peers));
    ml->peer_count = 0;
    ml->vpn_ip = 0;
    ml->derp.connected = false;
    ml->disco_local_port = 0;
    ml->stun_public_ip = 0;
    ml->stun_public_port = 0;
    memset(ml->stun_public_ip6, 0, sizeof(ml->stun_public_ip6));
    ml->stun_public_port6 = 0;
    ml->stun_has_ipv6 = false;
    ml->stun_secondary_port = 0;
    ml->stun_nat_checked = false;
    ml->nat_mapping_varies = false;

    if (ml->events) xEventGroupClearBits(ml->events, ML_EVT_ALL_BITS);
}

/* Free the context. Precondition: no task is running. */
static void ml_release(microlink_t *ml) {
    if (ml->config_httpd) {
        ml_config_httpd_deinit(ml->config_httpd);
        ml->config_httpd = NULL;
    }

    ml_release_run_resources(ml);

    if (ml->derp_tx_queue)     { vQueueDelete(ml->derp_tx_queue);     ml->derp_tx_queue = NULL; }
    if (ml->disco_rx_queue)    { vQueueDelete(ml->disco_rx_queue);    ml->disco_rx_queue = NULL; }
    if (ml->wg_rx_queue)       { vQueueDelete(ml->wg_rx_queue);       ml->wg_rx_queue = NULL; }
    if (ml->stun_rx_queue)     { vQueueDelete(ml->stun_rx_queue);     ml->stun_rx_queue = NULL; }
    if (ml->coord_cmd_queue)   { vQueueDelete(ml->coord_cmd_queue);   ml->coord_cmd_queue = NULL; }
    if (ml->peer_update_queue) { vQueueDelete(ml->peer_update_queue); ml->peer_update_queue = NULL; }
    if (ml->wg_wake)           { vSemaphoreDelete(ml->wg_wake);       ml->wg_wake = NULL; }
    if (ml->derp_wake_fd >= 0) { close(ml->derp_wake_fd);             ml->derp_wake_fd = -1; }
    if (ml->events)            { vEventGroupDelete(ml->events);       ml->events = NULL; }

    /* Clear keys from memory */
    memset(ml->machine_private_key, 0, 32);
    memset(ml->wg_private_key, 0, 32);
    memset(ml->disco_private_key, 0, 32);

    free(ml);

    bool last;
    portENTER_CRITICAL(&s_orphan_mux);
    last = (--s_live_contexts <= 0);
    if (s_live_contexts < 0) s_live_contexts = 0;
    portEXIT_CRITICAL(&s_orphan_mux);
    if (last) ml_peer_nvs_deinit();

    ESP_LOGI(TAG, "Destroyed");
}

static void ml_orphan_park(microlink_t *ml) {
    int slot = -1;
    portENTER_CRITICAL(&s_orphan_mux);
    for (int i = 0; i < ML_MAX_ORPHANS; i++) {
        if (!s_orphans[i]) { s_orphans[i] = ml; slot = i; break; }
    }
    portEXIT_CRITICAL(&s_orphan_mux);

    if (slot < 0) {
        /* Several teardowns in a row left tasks behind. A permanent leak is
         * still better than a use-after-free. */
        ESP_LOGE(TAG, "Orphan table full; context %p leaked", ml);
    } else {
        ESP_LOGW(TAG, "Context %p parked until its tasks exit (slot %d)", ml, slot);
    }
}

static void ml_reap_orphans(void) {
    for (int i = 0; i < ML_MAX_ORPHANS; i++) {
        microlink_t *ripe = NULL;
        portENTER_CRITICAL(&s_orphan_mux);
        if (s_orphans[i] && ml_tasks_alive(s_orphans[i]) == 0) {
            ripe = s_orphans[i];
            s_orphans[i] = NULL;
        }
        portEXIT_CRITICAL(&s_orphan_mux);
        if (ripe) {
            ESP_LOGW(TAG, "Freeing parked context %p (its tasks have exited)", ripe);
            ml_release(ripe);
        }
    }
}

/* True when called from one of this context's own worker tasks (e.g. from a
 * state callback). Such a caller can never see itself exit. */
static bool ml_called_from_worker(const microlink_t *ml) {
    TaskHandle_t self = xTaskGetCurrentTaskHandle();
    return self == ml->net_io_task || self == ml->derp_tx_task ||
           self == ml->coord_task || self == ml->wg_mgr_task;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

microlink_t *microlink_init(const microlink_config_t *config) {
    /* auth_key may be NULL or "": the device then registers without one
     * and the control plane asks for an interactive login
     * (ML_STATE_NEEDS_LOGIN, microlink_get_auth_url()). */
    if (!config) {
        ESP_LOGE(TAG, "Invalid config");
        return NULL;
    }

    /* Free any earlier context whose tasks have exited since its destroy */
    ml_reap_orphans();

    /* Tailnet packet filter (ACLs), see ml_filter.h */
#if defined(CONFIG_ML_PACKET_FILTER_ENFORCE)
    ml_filter_init(ML_FILTER_MODE_ENFORCE);
#elif defined(CONFIG_ML_PACKET_FILTER_LOG)
    ml_filter_init(ML_FILTER_MODE_LOG);
#else
    ml_filter_init(ML_FILTER_MODE_OFF);
#endif

    /* Route cJSON to PSRAM */
    cJSON_Hooks hooks = {
        .malloc_fn = cjson_psram_malloc,
        .free_fn = free
    };
    cJSON_InitHooks(&hooks);

    /* Allocate context from PSRAM */
    microlink_t *ml = ml_psram_calloc(1, sizeof(microlink_t));
    if (!ml) {
        ESP_LOGE(TAG, "Failed to allocate context");
        return NULL;
    }

    /* Copy config */
    ml->config = *config;
    if (ml->config.max_peers == 0) ml->config.max_peers = ML_MAX_PEERS;
    if (ml->config.max_peers > ML_MAX_PEERS) ml->config.max_peers = ML_MAX_PEERS;
    ml->config.enable_derp = true;  /* Always need DERP for relay */
#ifdef CONFIG_ML_CTRL_STREAMING_MAP_FETCH
    ml->config.streaming_map_fetch = true;
#endif

    /* Custom control plane from config struct (NVS override below still wins).
     * It is used as a DNS name (an AT command over the cellular bridge), in
     * HTTP Host headers and as the TLS server name, so it must be a plain
     * host name; reject rather than truncate or pass anything else through. */
    if (config->ctrl_host && config->ctrl_host[0]) {
        if (!ml_at_param_valid(ML_AT_PARAM_HOSTNAME, config->ctrl_host,
                               sizeof(ml->ctrl_host) - 1)) {
            ESP_LOGE(TAG, "Invalid ctrl_host: must be a host name of letters, "
                     "digits, '-' and '.' (max %u)", (unsigned)(sizeof(ml->ctrl_host) - 1));
            free(ml);
            return NULL;
        }
        strncpy(ml->ctrl_host, config->ctrl_host, sizeof(ml->ctrl_host) - 1);
        ESP_LOGI(TAG, "Control plane from config: %s", ml->ctrl_host);
    }
    if (config->ctrl_noise_pubkey) {
        memcpy(ml->ctrl_noise_pubkey, config->ctrl_noise_pubkey, 32);
        ml->ctrl_noise_pubkey_set = true;
    }

    /* Advertised subnet routes / exit node */
    const char *routes = config->advertise_routes;
#ifdef CONFIG_ML_ADVERTISE_ROUTES
    if (!routes) routes = CONFIG_ML_ADVERTISE_ROUTES;
#endif
    int nroutes = ml_routes_parse(routes, ml->routes, ML_MAX_ROUTES);
    int nroutes6 = ml_routes_parse6(routes, ml->routes6, ML_MAX_ROUTES);
    if (nroutes < 0 || nroutes6 < 0) {
        ESP_LOGE(TAG, "Invalid advertise_routes \"%s\": expected up to %d IPv4 and %d IPv6 "
                 "prefixes such as 192.168.1.0/24 or fd12:3456::/64", routes, ML_MAX_ROUTES, ML_MAX_ROUTES);
        free(ml);
        return NULL;
    }
#ifndef CONFIG_ML_ROUTER_IPV6
    if (nroutes6 > 0) {
        ESP_LOGE(TAG, "IPv6 routes in advertise_routes need CONFIG_ML_ROUTER_IPV6");
        free(ml);
        return NULL;
    }
#endif
#ifndef CONFIG_ML_SUBNET_ROUTER
    if (nroutes > 0 || nroutes6 > 0) {
        ESP_LOGE(TAG, "advertise_routes is set but CONFIG_ML_SUBNET_ROUTER is off "
                 "(the device could not forward the traffic)");
        free(ml);
        return NULL;
    }
#endif
    ml->route_count = (uint8_t)nroutes;
    ml->route6_count = (uint8_t)nroutes6;
    for (int i = 0; i < nroutes; i++) {
        char cidr[20];
        ml_routes_format(&ml->routes[i], cidr, sizeof(cidr));
        ESP_LOGI(TAG, "Advertising route %s%s", cidr,
                 ml->routes[i].len == 0 ? " (exit node)" : "");
    }
    for (int i = 0; i < nroutes6; i++) {
        char cidr[48];
        ml_routes6_format(&ml->routes6[i], cidr, sizeof(cidr));
        ESP_LOGI(TAG, "Advertising route %s", cidr);
    }

    ml->state = ML_STATE_IDLE;
    ml->coord_sock = -1;
    ml->disco_sock4 = -1;
    ml->disco_sock6 = -1;
    ml->stun_sock = -1;
    ml->stun_sock6 = -1;
    ml->derp.sockfd = -1;
    ml->derp_wake_fd = -1;   /* created by the DERP task (eventfd); before any
                              * error path, so ml_release() never closes fd 0 */

    /* Resolve timing (0 = use defaults from #defines) */
    ml->t_disco_heartbeat_ms = ml->config.disco_heartbeat_ms ? ml->config.disco_heartbeat_ms : ML_DISCO_HEARTBEAT_MS;
    ml->t_stun_interval_ms = ml->config.stun_interval_ms ? ml->config.stun_interval_ms : ML_STUN_RESTUN_INTERVAL_MS;
    ml->t_ctrl_watchdog_ms = ml->config.ctrl_watchdog_ms ? ml->config.ctrl_watchdog_ms : ML_CTRL_WATCHDOG_MS;

    /* Apply Kconfig priority peer if set and app didn't provide one */
    if (ml->config.priority_peer_ip == 0 && strlen(CONFIG_ML_PRIORITY_PEER_IP) > 0) {
        ml->config.priority_peer_ip = microlink_parse_ip(CONFIG_ML_PRIORITY_PEER_IP);
        if (ml->config.priority_peer_ip) {
            ESP_LOGI(TAG, "Priority peer from Kconfig: %s", CONFIG_ML_PRIORITY_PEER_IP);
        }
    }

    /* Load or generate persistent keys */
    if (load_or_generate_keys(ml) != ESP_OK) {
        free(ml);
        return NULL;
    }

    /* From here on, failures go through ml_release(), which undoes this. */
    portENTER_CRITICAL(&s_orphan_mux);
    s_live_contexts++;
    portEXIT_CRITICAL(&s_orphan_mux);

    /* Initialize peer NVS cache */
    ml_peer_nvs_init();

    /* Initialize HTTP config server (loads NVS peer allowlist + settings) */
    ml->config_httpd = ml_config_httpd_init();

    /* Override config with NVS-saved settings (web UI save → restart flow).
     * NVS settings take priority over Kconfig defaults.  Strings are copied
     * into ml->nvs_* buffers so the const char* pointers remain valid. */
    if (ml->config_httpd) {
        const char *nvs_auth = ml_config_get_auth_key(ml->config_httpd);
        if (nvs_auth) {
            strncpy(ml->nvs_auth_key, nvs_auth, sizeof(ml->nvs_auth_key) - 1);
            ml->config.auth_key = ml->nvs_auth_key;
            ESP_LOGI(TAG, "Auth key overridden from NVS (len=%d)", (int)strlen(nvs_auth));
        }
        /* Device name: full name takes priority, then prefix+MAC, then Kconfig */
        const char *nvs_full_name = ml_config_get_device_name_full(ml->config_httpd);
        if (nvs_full_name) {
            /* Full custom hostname (e.g. "sensor-tailscale") */
            strncpy(ml->nvs_device_name, nvs_full_name, sizeof(ml->nvs_device_name) - 1);
            ml->config.device_name = ml->nvs_device_name;
            ESP_LOGI(TAG, "Device name from NVS (full): %s", ml->nvs_device_name);
        } else {
            const char *nvs_prefix = ml_config_get_device_prefix(ml->config_httpd);
            if (nvs_prefix) {
                /* Device name = prefix + MAC suffix (e.g. "sensor-a1b2c3") */
                uint8_t mac[6];
                esp_read_mac(mac, ESP_MAC_WIFI_STA);
                snprintf(ml->nvs_device_name, sizeof(ml->nvs_device_name),
                         "%s-%02x%02x%02x", nvs_prefix, mac[3], mac[4], mac[5]);
                ml->config.device_name = ml->nvs_device_name;
                ESP_LOGI(TAG, "Device name from NVS (prefix): %s", ml->nvs_device_name);
            }
        }

        /* v2 overrides */
        uint8_t nvs_max = ml_config_get_max_peers(ml->config_httpd);
        if (nvs_max > 0 && nvs_max <= ML_MAX_PEERS) {
            ml->config.max_peers = nvs_max;
            ESP_LOGI(TAG, "Max peers overridden from NVS: %d", nvs_max);
        }
        uint16_t nvs_hb = ml_config_get_disco_heartbeat_ms(ml->config_httpd);
        if (nvs_hb > 0 && nvs_hb <= 60000) {
            ml->config.disco_heartbeat_ms = nvs_hb;
            ml->t_disco_heartbeat_ms = nvs_hb;
            ESP_LOGI(TAG, "DISCO heartbeat overridden from NVS: %dms", nvs_hb);
        }
        uint32_t nvs_pip = ml_config_get_priority_peer_ip(ml->config_httpd);
        if (nvs_pip > 0) {
            ml->config.priority_peer_ip = nvs_pip;
            char pip_str[16];
            microlink_ip_to_str(nvs_pip, pip_str);
            ESP_LOGI(TAG, "Priority peer overridden from NVS: %s", pip_str);
        }
        const char *nvs_ctrl = ml_config_get_ctrl_host(ml->config_httpd);
        if (nvs_ctrl) {
            strncpy(ml->ctrl_host, nvs_ctrl, sizeof(ml->ctrl_host) - 1);
            ESP_LOGI(TAG, "Control plane overridden from NVS: %s", ml->ctrl_host);
        }
        ml->debug_flags = ml_config_get_debug_flags(ml->config_httpd);
        if (ml->debug_flags) {
            ESP_LOGI(TAG, "Debug flags from NVS: 0x%02x", ml->debug_flags);
        }
    }

    /* Create event group */
    ml->events = xEventGroupCreate();
    if (!ml->events) {
        ESP_LOGE(TAG, "Failed to create event group");
        ml_release(ml);
        return NULL;
    }

    /* Create queues */
    ml->derp_tx_queue = xQueueCreate(ML_DERP_TX_QUEUE_DEPTH, sizeof(ml_derp_tx_item_t));
    ml->disco_rx_queue = xQueueCreate(ML_DISCO_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->wg_rx_queue = xQueueCreate(ML_WG_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->stun_rx_queue = xQueueCreate(ML_STUN_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->coord_cmd_queue = xQueueCreate(ML_COORD_CMD_QUEUE_DEPTH, sizeof(ml_coord_cmd_t));
    ml->peer_update_queue = xQueueCreate(ML_PEER_UPDATE_QUEUE_DEPTH, sizeof(ml_peer_update_t *));
    ml->wg_wake = xSemaphoreCreateBinary();

    if (!ml->derp_tx_queue || !ml->disco_rx_queue || !ml->wg_rx_queue ||
        !ml->stun_rx_queue || !ml->coord_cmd_queue || !ml->peer_update_queue ||
        !ml->wg_wake) {
        ESP_LOGE(TAG, "Failed to create queues");
        ml_release(ml);
        return NULL;
    }

    ESP_LOGI(TAG, "MicroLink v2 initialized (max_peers=%d)", ml->config.max_peers);
    return ml;
}

esp_err_t microlink_start(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    uint32_t stragglers = ml_tasks_alive(ml);
    if (stragglers) {
        /* A second generation of tasks would share the liveness bits with
         * the first, and the first to exit would clear the other's bit. */
        char names[40];
        ml_describe_tasks(stragglers, names, sizeof(names));
        ESP_LOGE(TAG, "Cannot start: tasks from the previous run still running:%s "
                      "(call microlink_stop() again)", names);
        return ESP_ERR_INVALID_STATE;
    }
    if (ml->started) {
        ESP_LOGW(TAG, "Already started (state=%d)", ml->state);
        return ESP_ERR_INVALID_STATE;
    }

    /* Start from a clean event group: a SHUTDOWN_REQUEST left over from the
     * previous stop would make every new task exit at once, and stale
     * COORD_REGISTERED/WG_READY/DERP_* bits would skip startup steps. */
    xEventGroupClearBits(ml->events, ML_EVT_ALL_BITS);
    ml->started = true;

    /* First boot of an OTA-updated firmware: arm its rollback timer */
    ml_ota_check_pending();
    ml->state = ML_STATE_WIFI_WAIT;

    /* Set WiFi TX power if configured */
    if (ml->config.wifi_tx_power_dbm > 0) {
        int8_t power_quarter_dbm = ml->config.wifi_tx_power_dbm * 4;
        esp_wifi_set_max_tx_power(power_quarter_dbm);
        ESP_LOGI(TAG, "WiFi TX power set to %d dBm", ml->config.wifi_tx_power_dbm);
    }

#ifdef CONFIG_ML_ZERO_COPY_WG
    /* Zero-copy mode: raw lwIP PCB replaces BSD socket for DISCO/WG UDP.
     * WG packets go directly to wireguardif_network_rx() from tcpip_thread.
     * DISCO packets go to SPSC ring buffer, STUN to existing queue. */
    if (ml_zerocopy_init(ml) != ESP_OK) {
        ESP_LOGE(TAG, "Zero-copy init failed, falling back to BSD socket");
        goto bsd_socket_fallback;
    }
    ESP_LOGI(TAG, "Zero-copy WG mode active (high-throughput)");
    goto skip_bsd_socket;

bsd_socket_fallback:
#endif
    /* Create DISCO/magicsock UDP socket (port 51820 = WireGuard standard)
     * This is the single socket for ALL direct UDP traffic: DISCO pings/pongs,
     * CallMeMaybe probes, and WireGuard encrypted data.
     * Matches v1 microlink_disco_init() and tailscale's pconn4. */
    ml->disco_sock4 = ml_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->disco_sock4 >= 0) {
        struct sockaddr_in bind_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(51820),
            .sin_addr.s_addr = INADDR_ANY,
        };
        if (ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            ESP_LOGW(TAG, "Failed to bind port 51820 (errno=%d), trying ephemeral", errno);
            bind_addr.sin_port = 0;
            ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        }

        /* Mark packets as DSCP 46 (Expedited Forwarding) → WMM AC_VO.
         * WiFi APs with WMM use shorter contention windows for voice-priority
         * traffic, reducing jitter on WireGuard/DISCO UDP packets. */
        int tos = 0xB8;  /* DSCP 46 = EF, TOS byte = 46 << 2 = 184 */
        setsockopt(ml->disco_sock4, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

        /* Set non-blocking for select() in net_io */
        int flags = ml_fcntl(ml->disco_sock4, F_GETFL, 0);
        ml_fcntl(ml->disco_sock4, F_SETFL, flags | O_NONBLOCK);

        /* Record the actual bound port (getsockname not wrapped — AT sockets use stored port) */
        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        getsockname(ml->disco_sock4, (struct sockaddr *)&local_addr, &addr_len);
        ml->disco_local_port = ntohs(local_addr.sin_port);
        ESP_LOGI(TAG, "DISCO/magicsock UDP socket bound to port %d", ml->disco_local_port);
    } else {
        ESP_LOGE(TAG, "Failed to create DISCO socket: errno=%d", errno);
    }
#ifdef CONFIG_ML_ZERO_COPY_WG
skip_bsd_socket:
    ;
#endif

    /* Create tasks. Each liveness bit goes up before its create: from the
     * moment the task exists it may hold the context, and only the task may
     * clear the bit again. If a create fails, no task exists to clear that
     * bit, so it is cleared here and the tasks already running are joined
     * by microlink_stop(). */
    static const struct {
        TaskFunction_t fn;
        const char *name;
        uint32_t stack;
        UBaseType_t prio;
        BaseType_t core;
        uint32_t bit;
    } tasks[] = {
        { ml_net_io_task,  "ml_net_io",  ML_TASK_NET_IO_STACK,  ML_TASK_NET_IO_PRIO,  ML_TASK_NET_IO_CORE,  ML_TASK_BIT_NET_IO },
        { ml_derp_tx_task, "ml_derp_tx", ML_TASK_DERP_TX_STACK, ML_TASK_DERP_TX_PRIO, ML_TASK_DERP_TX_CORE, ML_TASK_BIT_DERP_TX },
        { ml_coord_task,   "ml_coord",   ML_TASK_COORD_STACK,   ML_TASK_COORD_PRIO,   ML_TASK_COORD_CORE,   ML_TASK_BIT_COORD },
        { ml_wg_mgr_task,  "ml_wg_mgr",  ML_TASK_WG_MGR_STACK,  ML_TASK_WG_MGR_PRIO,  ML_TASK_WG_MGR_CORE,  ML_TASK_BIT_WG_MGR },
    };
    TaskHandle_t *handles[] = { &ml->net_io_task, &ml->derp_tx_task, &ml->coord_task, &ml->wg_mgr_task };

    for (size_t i = 0; i < sizeof(tasks) / sizeof(tasks[0]); i++) {
        __atomic_fetch_or(&ml->tasks_alive, tasks[i].bit, __ATOMIC_RELEASE);
        if (xTaskCreatePinnedToCore(tasks[i].fn, tasks[i].name, tasks[i].stack, ml,
                                    tasks[i].prio, handles[i], tasks[i].core) != pdPASS) {
            __atomic_fetch_and(&ml->tasks_alive, ~tasks[i].bit, __ATOMIC_RELEASE);
            *handles[i] = NULL;
            ESP_LOGE(TAG, "Failed to create %s task (free internal=%u psram=%u); rolling back",
                     tasks[i].name,
                     (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                     (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
            microlink_stop(ml);
            return ESP_FAIL;
        }
    }

    /* WiFi is expected to be connected before microlink_start() is called.
     * Signal the event so coord/wg_mgr tasks proceed immediately. */
    xEventGroupSetBits(ml->events, ML_EVT_WIFI_CONNECTED);

    /* Signal coord task to start connecting */
    ml_coord_cmd_t cmd = ML_CMD_CONNECT;
    xQueueSend(ml->coord_cmd_queue, &cmd, 0);

    /* Start HTTP config server (binds port 80, serves config page + REST API) */
    if (ml->config_httpd) {
        ml_config_httpd_start(ml->config_httpd, ml);
    }

    ESP_LOGI(TAG, "All tasks started");
    return ESP_OK;
}

esp_err_t microlink_rebind(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    if (ml->state == ML_STATE_IDLE) return ESP_ERR_INVALID_STATE;

    ESP_LOGI(TAG, "=== Rebinding to new network interface ===");

    /* Step 1: Invalidate socket FDs FIRST, then delay to let net_io_task's
     * select() cycle complete (50ms timeout). Only THEN close the old FDs.
     * Closing a socket while another thread has it in select() deadlocks
     * on lwIP's global socket lock. */
    int old_disco = ml->disco_sock4;
    int old_stun = ml->stun_sock;
    int old_stun6 = ml->stun_sock6;

    /* Invalidate — net_io_task will skip these on next iteration */
    ml->disco_sock4 = -1;
    ml->stun_sock = -1;
    ml->stun_sock6 = -1;

    /* Wait for net_io_task select() to cycle out (50ms timeout + margin) */
    vTaskDelay(pdMS_TO_TICKS(100));

    /* Now safe to close the old FDs */
    if (old_disco >= 0) ml_close_sock(old_disco);
    if (old_stun >= 0) ml_close_sock(old_stun);
    if (old_stun6 >= 0) ml_close_sock(old_stun6);
    ESP_LOGI(TAG, "Rebind: closed DISCO + STUN sockets");

    /* Step 2: Signal coord to reconnect. ML_CMD_FORCE_RECONNECT closes
     * the coord socket, resets Noise state, and re-enters the
     * STUN → DNS → TCP → Noise → Register → MapRequest flow.
     * Peers and WG state are preserved. */
    xEventGroupClearBits(ml->events, ML_EVT_COORD_REGISTERED);
    ml_coord_cmd_t cmd = ML_CMD_FORCE_RECONNECT;
    xQueueSend(ml->coord_cmd_queue, &cmd, pdMS_TO_TICKS(100));

    /* Step 3: Signal DERP to reconnect. ML_EVT_DERP_RECONNECT triggers
     * derp_tx_task to close TLS, then reconnect with full handshake.
     * Pending TX packets are drained but WG state is preserved. */
    xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);
    xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
    ESP_LOGI(TAG, "Rebind: signaled coord + DERP to reconnect");

    /* Step 4: Brief delay for coord/DERP to process reconnect signals */
    vTaskDelay(pdMS_TO_TICKS(200));

    /* Step 5: Recreate DISCO UDP socket on the new interface */
#ifdef CONFIG_ML_ZERO_COPY_WG
    ml_zerocopy_deinit(ml);
    if (ml_zerocopy_init(ml) == ESP_OK) {
        ESP_LOGI(TAG, "Rebind: zero-copy DISCO PCB recreated");
        goto rebind_wg_update;
    }
    ESP_LOGW(TAG, "Rebind: zero-copy init failed, using BSD socket fallback");
#endif
    ml->disco_sock4 = ml_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->disco_sock4 >= 0) {
        struct sockaddr_in bind_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(51820),
            .sin_addr.s_addr = INADDR_ANY,
        };
        if (ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            bind_addr.sin_port = 0;
            ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        }
        int tos = 0xB8;
        setsockopt(ml->disco_sock4, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        int flags = ml_fcntl(ml->disco_sock4, F_GETFL, 0);
        ml_fcntl(ml->disco_sock4, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        getsockname(ml->disco_sock4, (struct sockaddr *)&local_addr, &addr_len);
        ml->disco_local_port = ntohs(local_addr.sin_port);
        ESP_LOGI(TAG, "Rebind: DISCO socket rebound to port %d", ml->disco_local_port);
    } else {
        ESP_LOGE(TAG, "Rebind: failed to create DISCO socket: errno=%d", errno);
    }

#ifdef CONFIG_ML_ZERO_COPY_WG
rebind_wg_update:
#endif
    /* Step 6: Update WG output mode for new transport */
    ml_wg_mgr_update_transport(ml);

    ESP_LOGI(TAG, "=== Rebind complete — waiting for coord+DERP reconnect ===");
    return ESP_OK;
}

esp_err_t microlink_stop(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    if (!ml->events) return ESP_ERR_INVALID_STATE;
    if (!ml->started && ml_tasks_alive(ml) == 0) return ESP_OK;  /* already stopped */
    if (ml_called_from_worker(ml)) {
        ESP_LOGE(TAG, "microlink_stop() called from a MicroLink task (callback?); "
                      "call it from an application task");
        return ESP_ERR_INVALID_STATE;
    }

    int64_t t_start = esp_timer_get_time();
    ESP_LOGI(TAG, "Stopping...");
    xEventGroupSetBits(ml->events, ML_EVT_SHUTDOWN_REQUEST);

    /* The config UI's handlers call into ml; stop serving them first. */
    ML_HEAP_TRACE("stop: begin");
    if (ml->config_httpd) {
        ml_config_httpd_stop(ml->config_httpd);
        ML_HEAP_TRACE("stop: config UI detached");
    }

    /* coord's reconnect backoff blocks on its command queue for up to 30 s;
     * a command wakes it, and the loop then sees the shutdown bit. */
    ml_coord_cmd_t wake = ML_CMD_DISCONNECT;
    xQueueSendToFront(ml->coord_cmd_queue, &wake, 0);

    /* Tasks never call vTaskDelete() on each other; each one exits by itself
     * through ml_task_exit(). Give them a moment to notice the shutdown bit,
     * then shut down the sockets the network tasks may be blocked reading
     * (coord's MapResponse read waits up to 60 s, DERP TLS reads up to 10 s). */
    uint32_t alive = ml_join_tasks(ml, ML_STOP_GRACE_MS);
    uint32_t waited = ML_STOP_GRACE_MS;
    int coord_fd_done = -1, derp_fd_done = -1;
    while (alive && waited < CONFIG_ML_STOP_TIMEOUT_MS) {
        /* A task that was between connections (DNS, TCP connect) may open a
         * new socket after the first pass; shut that one down too. Each
         * descriptor is shut down once. */
        int fd = ml->coord_sock;
        if ((alive & ML_TASK_BIT_COORD) && fd >= 0 && fd != coord_fd_done) {
            ml_unblock_socket(fd);
            coord_fd_done = fd;
        }
        fd = ml->derp.sockfd;
        if ((alive & ML_TASK_BIT_DERP_TX) && fd >= 0 && fd != derp_fd_done) {
            ml_unblock_socket(fd);
            derp_fd_done = fd;
        }
        uint32_t slice = CONFIG_ML_STOP_TIMEOUT_MS - waited;
        if (slice > 2000) slice = 2000;
        alive = ml_join_tasks(ml, slice);
        waited += slice;
    }

    int join_ms = (int)((esp_timer_get_time() - t_start) / 1000);
    ML_HEAP_TRACE("stop: tasks joined");
    ml->state = ML_STATE_IDLE;

    if (alive) {
        /* Releasing anything now would pull it out from under a live task.
         * Keep everything; another microlink_stop() resumes the wait, and
         * microlink_destroy() parks the context instead of freeing it. */
        char names[40];
        ml_describe_tasks(alive, names, sizeof(names));
        ESP_LOGE(TAG, "Stop timed out after %d ms; still running:%s", join_ms, names);
        return ESP_ERR_TIMEOUT;
    }

    ml_release_run_resources(ml);
    ML_HEAP_TRACE("stop: run resources freed");
    ml->started = false;
    ml->state = ML_STATE_IDLE;
    ESP_LOGI(TAG, "Stopped (all tasks exited in %d ms)", join_ms);
    return ESP_OK;
}

void microlink_destroy(microlink_t *ml) {
    if (!ml) return;

    if (ml_called_from_worker(ml)) {
        /* Cannot join ourselves; freeing would be a use-after-free. */
        ESP_LOGE(TAG, "microlink_destroy() called from a MicroLink task; ignored");
        return;
    }

    microlink_stop(ml);
    ml_filter_reset();

    /* Free anything parked by an earlier teardown that has drained since. */
    ml_reap_orphans();

    uint32_t alive = ml_tasks_alive(ml);
    if (alive) {
        char names[40];
        ml_describe_tasks(alive, names, sizeof(names));
        ESP_LOGE(TAG, "Deferring free:%s still running", names);
        ml_orphan_park(ml);
        return;
    }

    ml_release(ml);
}

/* ============================================================================
 * State Queries
 * ========================================================================== */

microlink_state_t microlink_get_state(const microlink_t *ml) {
    return ml ? ml->state : ML_STATE_IDLE;
}

bool microlink_is_connected(const microlink_t *ml) {
    return ml && ml->state == ML_STATE_CONNECTED;
}

static bool lan_netif_up(esp_netif_t *netif, void *arg) {
    (void)arg;
    if (esp_netif_get_flags(netif) & ESP_NETIF_FLAG_IS_PPP) return false;
    const char *key = esp_netif_get_ifkey(netif);
    if (!key || (strncmp(key, "WIFI_STA", 8) != 0 && strncmp(key, "ETH", 3) != 0)) return false;
    esp_netif_ip_info_t info;
    return esp_netif_is_netif_up(netif) &&
           esp_netif_get_ip_info(netif, &info) == ESP_OK && info.ip.addr != 0;
}

bool ml_lan_ipv4(uint32_t *ip_out) {
    esp_netif_t *netif = esp_netif_get_default_netif();
    if (!netif || !lan_netif_up(netif, NULL)) netif = esp_netif_find_if(lan_netif_up, NULL);
    esp_netif_ip_info_t info;
    if (!netif || esp_netif_get_ip_info(netif, &info) != ESP_OK || info.ip.addr == 0) return false;
    *ip_out = ntohl(info.ip.addr);
    return true;
}

uint32_t microlink_get_vpn_ip(const microlink_t *ml) {
    return ml ? ml->vpn_ip : 0;
}

int microlink_get_peer_count(const microlink_t *ml) {
    return ml ? ml->peer_count : 0;
}

esp_err_t microlink_get_peer_info(const microlink_t *ml, int index, microlink_peer_info_t *info) {
    if (!ml || !info || index < 0 || index >= ml->peer_count) {
        return ESP_ERR_INVALID_ARG;
    }
    const ml_peer_t *p = &ml->peers[index];
    info->vpn_ip = p->vpn_ip;
    strncpy(info->hostname, p->hostname, sizeof(info->hostname) - 1);
    memcpy(info->public_key, p->public_key, 32);
    info->online = p->online;
    info->direct_path = p->has_direct_path;
    return ESP_OK;
}

/* ============================================================================
 * Send API
 * ========================================================================== */

esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                          const uint8_t *data, size_t len) {
    /* This used to put the raw payload into a DERP SendPacket - NOT through
     * WireGuard - so the relay operator could read it and the peer discarded
     * it. Refuse instead of silently leaking data; use microlink_udp_* or
     * microlink_tcp_*, which go through the encrypted tunnel. */
    (void)ml; (void)dest_vpn_ip; (void)data; (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

/* ============================================================================
 * Callbacks
 * ========================================================================== */

void microlink_set_state_callback(microlink_t *ml, microlink_state_cb_t cb, void *user_data) {
    if (ml) { ml->state_cb = cb; ml->state_cb_data = user_data; }
}

void microlink_set_peer_callback(microlink_t *ml, microlink_peer_cb_t cb, void *user_data) {
    if (ml) { ml->peer_cb = cb; ml->peer_cb_data = user_data; }
}

void microlink_set_data_callback(microlink_t *ml, microlink_data_cb_t cb, void *user_data) {
    if (ml) { ml->data_cb = cb; ml->data_cb_data = user_data; }
}

/* ============================================================================
 * Utilities
 * ========================================================================== */

void microlink_ip_to_str(uint32_t ip, char *buf) {
    snprintf(buf, 16, "%lu.%lu.%lu.%lu",
             (unsigned long)((ip >> 24) & 0xFF),
             (unsigned long)((ip >> 16) & 0xFF),
             (unsigned long)((ip >> 8) & 0xFF),
             (unsigned long)(ip & 0xFF));
}

uint32_t microlink_parse_ip(const char *ip_str) {
    if (!ip_str) return 0;
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

const char *microlink_default_device_name(void) {
    static char name[48] = {0};
    if (name[0] == 0) {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);

        /* Use ML_DEVICE_NAME as prefix if configured, otherwise "esp32" */
        const char *prefix = CONFIG_ML_DEVICE_NAME;
        if (!prefix || !prefix[0]) prefix = "esp32";
        snprintf(name, sizeof(name), "%s-%02x%02x%02x", prefix, mac[3], mac[4], mac[5]);
    }
    return name;
}

const char *microlink_imei_device_name(void) {
#ifdef CONFIG_ML_ENABLE_CELLULAR
    static char name[48] = {0};  /* prefix + "-" + 15-digit IMEI + null */
    const char *imei = ml_cellular_get_imei();
    if (imei && imei[0]) {
        const char *prefix = CONFIG_ML_DEVICE_NAME;
        if (!prefix || !prefix[0]) prefix = "esp32";
        snprintf(name, sizeof(name), "%s-%s", prefix, imei);
        return name;
    }
#endif
    return NULL;
}

uint64_t ml_get_time_ms(void) {
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

/* ============================================================================
 * MagicDNS — Resolve tailnet hostnames against peer list
 * ========================================================================== */

/* Case-insensitive string compare (limited to len bytes) */
static int strncasecmp_local(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

uint32_t microlink_resolve(const microlink_t *ml, const char *hostname) {
    if (!ml || !hostname || hostname[0] == '\0') return 0;

    size_t query_len = strlen(hostname);

    for (int i = 0; i < ml->peer_count; i++) {
        const ml_peer_t *p = &ml->peers[i];
        if (!p->active || p->hostname[0] == '\0') continue;

        /* 1. Exact match (case-insensitive) */
        if (strncasecmp_local(p->hostname, hostname, sizeof(p->hostname)) == 0) {
            return p->vpn_ip;
        }

        /* 2. Prefix match: query "npc1" matches peer "npc1.tail12345.ts.net"
         * The query must match up to the first '.' in the peer hostname. */
        const char *dot = strchr(p->hostname, '.');
        if (dot) {
            size_t short_len = (size_t)(dot - p->hostname);
            if (query_len == short_len &&
                strncasecmp_local(p->hostname, hostname, short_len) == 0) {
                return p->vpn_ip;
            }
        }
    }

    return 0;  /* Not found */
}
