/**
 * @file main.c
 * @brief MicroLink v2 Basic Connect + Messaging Example
 *
 * Connects to a Tailscale network, then:
 * - Listens on UDP port 9000 for incoming messages (logs + echoes them back)
 * - If TARGET_PEER_IP is set, periodically sends "hello from ESP32" to that peer
 *
 * Test from a PC on the same Tailscale network:
 *   Receive:  nc -lu 9000
 *   Send:     echo "hello from PC" | nc -u <ESP32_VPN_IP> 9000
 */

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "qrcode.h"

#include "microlink.h"
#include "microlink_internal.h"  /* For task handle access (diagnostic) */
#include "ml_config_httpd.h"     /* NVS WiFi override at boot */

static const char *TAG = "main";

#define MSG_PORT        9000
#define MSG_SEND_INTERVAL_MS 5000

/* WiFi credentials — start with Kconfig defaults, NVS may override */
static char wifi_ssid[33]     = CONFIG_ML_WIFI_SSID;
static char wifi_password[65] = CONFIG_ML_WIFI_PASSWORD;

/* Multi-SSID support */
static ml_config_wifi_list_t wifi_list;
static int wifi_list_count = 0;      /* 0 = single SSID mode */
static int current_wifi_idx = 0;
static int wifi_retry_count = 0;
#define WIFI_MAX_RETRIES_PER_SSID 3

/* WiFi event group */
static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

/* MicroLink handle */
static microlink_t *ml = NULL;

/* UDP socket */
static microlink_udp_socket_t *udp_sock = NULL;

/* Message counters */
static uint32_t msg_tx_count = 0;
static uint32_t msg_rx_count = 0;

/* ============================================================================
 * UDP RX Callback (called from dedicated RX task)
 * ========================================================================== */

static void on_udp_rx(microlink_udp_socket_t *sock, uint32_t src_ip, uint16_t src_port,
                       const uint8_t *data, size_t len, void *user_data) {
    msg_rx_count++;
    char ip_str[16];
    microlink_ip_to_str(src_ip, ip_str);

    /* Log the message (null-terminate for safe printing) */
    char msg[256];
    size_t copy_len = (len < sizeof(msg) - 1) ? len : sizeof(msg) - 1;
    memcpy(msg, data, copy_len);
    msg[copy_len] = '\0';
    /* Strip trailing newline if present */
    if (copy_len > 0 && msg[copy_len - 1] == '\n') msg[copy_len - 1] = '\0';

    ESP_LOGI(TAG, "UDP RX #%lu from %s:%u [%d bytes]: \"%s\"",
             (unsigned long)msg_rx_count, ip_str, src_port, (int)len, msg);

    /* Echo back with prefix */
    char reply[300];
    int reply_len = snprintf(reply, sizeof(reply), "ECHO: %s", msg);
    if (reply_len > 0) {
        esp_err_t err = microlink_udp_send(sock, src_ip, src_port, reply, reply_len);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "UDP TX echo -> %s:%u", ip_str, src_port);
        } else {
            ESP_LOGW(TAG, "UDP TX echo failed: %d (handshake in progress)", err);
        }
    }
}

/* ============================================================================
 * Callbacks
 * ========================================================================== */

static void on_state_change(microlink_t *ml_handle, microlink_state_t state, void *user_data) {
    const char *state_names[] = {
        "IDLE", "WIFI_WAIT", "CONNECTING", "REGISTERING",
        "CONNECTED", "RECONNECTING", "ERROR", "AUTH_FAILED", "NEEDS_LOGIN"
    };
    const char *name = (state < sizeof(state_names)/sizeof(state_names[0]))
                       ? state_names[state] : "UNKNOWN";
    ESP_LOGI(TAG, "MicroLink state: %s", name);

    if (state == ML_STATE_CONNECTED) {
        uint32_t ip = microlink_get_vpn_ip(ml_handle);
        char ip_str[16];
        microlink_ip_to_str(ip, ip_str);
        ESP_LOGI(TAG, "Connected! VPN IP: %s", ip_str);
    }

    /* No auth key configured: show the login URL (and a QR code of it on
     * the serial console). Opening it adds this device to your tailnet, so
     * it is printed only here, for whoever has the serial port. */
    if (state == ML_STATE_NEEDS_LOGIN) {
        char url[MICROLINK_AUTH_URL_MAX];
        if (microlink_get_auth_url(ml_handle, url, sizeof(url)) == ESP_OK) {
            printf("\nTo add this device to your tailnet, open:\n\n    %s\n\n", url);
            esp_qrcode_config_t qr = ESP_QRCODE_CONFIG_DEFAULT();
            esp_qrcode_generate(&qr, url);
        }
    }
}

static void on_peer_update(microlink_t *ml_handle, const microlink_peer_info_t *peer,
                             void *user_data) {
    char ip_str[16];
    microlink_ip_to_str(peer->vpn_ip, ip_str);
    ESP_LOGI(TAG, "Peer: %s (%s) online=%d direct=%d",
             peer->hostname, ip_str, peer->online, peer->direct_path);
}

/* ============================================================================
 * WiFi Setup
 * ========================================================================== */

/* Switch to the next WiFi SSID in the list (round-robin) */
static void wifi_try_next(void) {
    if (wifi_list_count <= 1) {
        /* Single SSID: just reconnect */
        esp_wifi_connect();
        return;
    }

    wifi_retry_count++;
    if (wifi_retry_count >= WIFI_MAX_RETRIES_PER_SSID) {
        wifi_retry_count = 0;
        current_wifi_idx = (current_wifi_idx + 1) % wifi_list_count;
    }

    /* Update wifi_config with new SSID/pass */
    ml_config_wifi_entry_t *e = &wifi_list.entries[current_wifi_idx];
    wifi_config_t wifi_config = {
        .sta = { .threshold.authmode = WIFI_AUTH_WPA2_PSK },
    };
    strncpy((char *)wifi_config.sta.ssid, e->ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, e->pass, sizeof(wifi_config.sta.password) - 1);

    ESP_LOGI(TAG, "WiFi trying #%d/%d: %s (retry %d/%d)",
             current_wifi_idx + 1, wifi_list_count, e->ssid,
             wifi_retry_count + 1, WIFI_MAX_RETRIES_PER_SSID);

    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_connect();
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disc = (wifi_event_sta_disconnected_t *)event_data;
        ESP_LOGW(TAG, "WiFi disconnected, reason=%d", disc->reason);
        wifi_try_next();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi connected to %s, IP: " IPSTR,
                 wifi_list_count > 0 ? wifi_list.entries[current_wifi_idx].ssid : wifi_ssid,
                 IP2STR(&event->ip_info.ip));
        wifi_retry_count = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init(void) {
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                    ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                    IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    strncpy((char *)wifi_config.sta.ssid, wifi_ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, wifi_password, sizeof(wifi_config.sta.password) - 1);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Disable WiFi power save for low-latency WireGuard traffic.
     * ESP-IDF defaults to WIFI_PS_MIN_MODEM which adds up to one DTIM
     * interval (100-300ms) of delay per packet wake cycle. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_LOGI(TAG, "WiFi init complete (PS=NONE), connecting to %s...", wifi_ssid);
}

/* ============================================================================
 * Stop/start lifecycle test (CONFIG_ML_EXAMPLE_LIFECYCLE_CYCLES > 0)
 * ========================================================================== */

#if CONFIG_ML_EXAMPLE_LIFECYCLE_CYCLES > 0
static bool wait_connected(int timeout_s) {
    for (int i = 0; i < timeout_s * 2; i++) {
        if (microlink_is_connected(ml)) return true;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    return false;
}

static void log_heap(const char *what, int cycle, int total) {
    ESP_LOGI(TAG, "LIFECYCLE %d/%d: %s heap internal=%u psram=%u min_internal=%u",
             cycle, total, what,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
             (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
}

/* Returns true if every cycle stopped cleanly and reconnected. The handle in
 * `ml` is replaced on destroy/init cycles; callbacks are re-registered. */
static bool lifecycle_test(const microlink_config_t *config) {
    const int total = CONFIG_ML_EXAMPLE_LIFECYCLE_CYCLES;
    int failures = 0;
    size_t base_int = 0, base_ps = 0;

    ESP_LOGI(TAG, "LIFECYCLE: starting %d stop/start cycles", total);
    /* Per-step free-heap trace inside microlink_stop() and the task exits.
     * Only printed when built with CONFIG_LOG_MAXIMUM_LEVEL_DEBUG=y. */
    esp_log_level_set("ml_heap", ESP_LOG_DEBUG);

    for (int c = 1; c <= total; c++) {
        int variant = (c - 1) % 3;   /* 0 = connected, 1 = mid-connect, 2 = destroy */

        if (variant == 1) {
            /* Stop while coord is still registering / reading the netmap */
            vTaskDelay(pdMS_TO_TICKS(3000));
            ESP_LOGI(TAG, "LIFECYCLE %d/%d: stopping mid-connect (state=%d)",
                     c, total, microlink_get_state(ml));
        } else if (!wait_connected(120)) {
            ESP_LOGE(TAG, "LIFECYCLE %d/%d: FAIL not connected within 120 s", c, total);
            failures++;
        } else {
            ESP_LOGI(TAG, "LIFECYCLE %d/%d: connected, %d peers",
                     c, total, microlink_get_peer_count(ml));
        }

        int64_t t0 = esp_timer_get_time();
        esp_err_t err = microlink_stop(ml);
        int stop_ms = (int)((esp_timer_get_time() - t0) / 1000);
        ESP_LOGI(TAG, "LIFECYCLE %d/%d: stop -> %s in %d ms",
                 c, total, esp_err_to_name(err), stop_ms);
        if (err != ESP_OK) failures++;

        if (variant == 2) {
            microlink_destroy(ml);
            ml = microlink_init(config);
            if (!ml) {
                ESP_LOGE(TAG, "LIFECYCLE %d/%d: FAIL microlink_init", c, total);
                return false;
            }
            microlink_set_state_callback(ml, on_state_change, NULL);
            microlink_set_peer_callback(ml, on_peer_update, NULL);
            ESP_LOGI(TAG, "LIFECYCLE %d/%d: destroyed and re-initialized", c, total);
        }

        /* Let the idle task reclaim the exited tasks' stacks first */
        vTaskDelay(pdMS_TO_TICKS(200));
        log_heap("stopped", c, total);
        if (c == 1) {
            base_int = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
            base_ps = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        }

        err = microlink_start(ml);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "LIFECYCLE %d/%d: FAIL start -> %s", c, total, esp_err_to_name(err));
            return false;
        }
        log_heap("started", c, total);
    }

    if (!wait_connected(120)) {
        ESP_LOGE(TAG, "LIFECYCLE: FAIL not connected after the last cycle");
        failures++;
    }

    /* Compare the free heap in the stopped state: the first cycle against the
     * last one. Before the lifecycle fixes each cycle lost ~15 KB (WG device)
     * plus whatever was queued. */
    microlink_stop(ml);
    vTaskDelay(pdMS_TO_TICKS(200));
    long d_int = (long)base_int - (long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    long d_ps = (long)base_ps - (long)heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    ESP_LOGI(TAG, "LIFECYCLE: heap lost since cycle 1: internal=%ld psram=%ld bytes (%d cycles)",
             d_int, d_ps, total);
    bool leak = total > 1 && (d_int + d_ps) / (total - 1 > 0 ? total - 1 : 1) > 1024;
    if (leak) {
        ESP_LOGE(TAG, "LIFECYCLE: more than 1 KB lost per cycle");
        failures++;
    }
    ESP_ERROR_CHECK(microlink_start(ml));

    ESP_LOGI(TAG, "LIFECYCLE RESULT: %s (%d cycles, %d failures)",
             failures ? "FAIL" : "PASS", total, failures);
    return failures == 0;
}
#endif /* CONFIG_ML_EXAMPLE_LIFECYCLE_CYCLES > 0 */

/* ============================================================================
 * Main
 * ========================================================================== */

void app_main(void) {
    /* Initialize NVS (required for WiFi + MicroLink key storage) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "MicroLink v2 Basic Connect + Messaging Example");
    ESP_LOGI(TAG, "Free heap: %lu bytes (PSRAM: %lu bytes)",
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    /* Check NVS for saved WiFi credentials (from web config UI) */
    memset(&wifi_list, 0, sizeof(wifi_list));
    wifi_list.active_idx = 0xFF;

    if (ml_config_get_wifi_list(&wifi_list) && wifi_list.count > 1) {
        /* Multi-SSID mode */
        wifi_list_count = wifi_list.count;
        current_wifi_idx = 0;
        strncpy(wifi_ssid, wifi_list.entries[0].ssid, sizeof(wifi_ssid) - 1);
        strncpy(wifi_password, wifi_list.entries[0].pass, sizeof(wifi_password) - 1);
        ESP_LOGI(TAG, "WiFi multi-SSID: %d networks (first: %s)", wifi_list_count, wifi_ssid);
        for (int i = 0; i < wifi_list_count; i++) {
            ESP_LOGI(TAG, "  WiFi #%d: %s", i + 1, wifi_list.entries[i].ssid);
        }
    } else if (ml_config_get_nvs_wifi(wifi_ssid, sizeof(wifi_ssid),
                                       wifi_password, sizeof(wifi_password))) {
        ESP_LOGI(TAG, "Using NVS WiFi: %s", wifi_ssid);
    } else {
        ESP_LOGI(TAG, "Using Kconfig WiFi: %s", wifi_ssid);
    }

    /* Initialize WiFi */
    wifi_init();

    /* Wait for WiFi connection */
    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT,
                         pdFALSE, pdTRUE, portMAX_DELAY);

    /* Initialize MicroLink
     * Auth key and device name come from Kconfig here, but microlink_init()
     * will override them with NVS-saved values if available (from web config UI). */
    microlink_config_t config = {
        .auth_key = CONFIG_ML_TAILSCALE_AUTH_KEY,
        .device_name = CONFIG_ML_DEVICE_NAME,
        .enable_derp = true,
        .enable_stun = true,
        .enable_disco = true,
        .max_peers = CONFIG_ML_MAX_PEERS,
        .wifi_tx_power_dbm = 13,  /* Reduced for thermal management */
    };

    ml = microlink_init(&config);
    if (!ml) {
        ESP_LOGE(TAG, "Failed to initialize MicroLink");
        return;
    }

    /* Register callbacks */
    microlink_set_state_callback(ml, on_state_change, NULL);
    microlink_set_peer_callback(ml, on_peer_update, NULL);

    /* Start connecting */
    ESP_ERROR_CHECK(microlink_start(ml));

    /* Wait for CONNECTED state before creating UDP socket */
    while (!microlink_is_connected(ml)) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }

#if CONFIG_ML_EXAMPLE_LIFECYCLE_CYCLES > 0
    /* Runs before the UDP socket exists: sockets created with
     * microlink_udp_create() must be closed before stopping MicroLink. */
    lifecycle_test(&config);
    while (!microlink_is_connected(ml)) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
#endif

    /* Create UDP socket on port 9000 */
    udp_sock = microlink_udp_create(ml, MSG_PORT);
    if (!udp_sock) {
        ESP_LOGE(TAG, "Failed to create UDP socket");
    } else {
        ESP_LOGI(TAG, "UDP socket listening on port %d", MSG_PORT);
        microlink_udp_set_rx_callback(udp_sock, on_udp_rx, NULL);
    }

    /* Parse target peer IP from Kconfig (if set) */
    uint32_t target_ip = 0;
    const char *target_ip_str = CONFIG_ML_EXAMPLE_TARGET_PEER_IP;
    if (target_ip_str && target_ip_str[0] != '\0') {
        target_ip = microlink_parse_ip(target_ip_str);
        if (target_ip != 0) {
            ESP_LOGI(TAG, "Will send messages to %s:%d every %dms",
                     target_ip_str, MSG_PORT, MSG_SEND_INTERVAL_MS);
        } else {
            ESP_LOGW(TAG, "Invalid target IP: '%s'", target_ip_str);
        }
    } else {
        ESP_LOGI(TAG, "No target peer IP configured (receive-only mode)");
    }

    /* Main loop */
    uint64_t last_send_ms = 0;
    uint64_t last_status_ms = 0;

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));

        uint64_t now = (uint64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);

        /* Periodic send to target peer */
        if (udp_sock && target_ip != 0 && now - last_send_ms >= MSG_SEND_INTERVAL_MS) {
            last_send_ms = now;
            msg_tx_count++;
            char msg[128];
            int msg_len = snprintf(msg, sizeof(msg), "hello from ESP32 #%lu", (unsigned long)msg_tx_count);
            esp_err_t err = microlink_udp_send(udp_sock, target_ip, MSG_PORT, msg, msg_len);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "UDP TX #%lu -> %s:%d: \"%s\"",
                         (unsigned long)msg_tx_count, target_ip_str, MSG_PORT, msg);
            } else {
                ESP_LOGW(TAG, "UDP TX #%lu FAILED (err=%d, WG handshake in progress)",
                         (unsigned long)msg_tx_count, err);
            }
        }

        /* Periodic status (every 30s) */
        if (now - last_status_ms >= 30000) {
            last_status_ms = now;

            if (microlink_is_connected(ml)) {
                int peer_count = microlink_get_peer_count(ml);
                ESP_LOGI(TAG, "Status: CONNECTED | Peers: %d | TX: %lu | RX: %lu | Heap: %lu",
                         peer_count, (unsigned long)msg_tx_count, (unsigned long)msg_rx_count,
                         (unsigned long)esp_get_free_heap_size());

                for (int i = 0; i < peer_count; i++) {
                    microlink_peer_info_t info;
                    if (microlink_get_peer_info(ml, i, &info) == ESP_OK) {
                        char ip_str[16];
                        microlink_ip_to_str(info.vpn_ip, ip_str);
                        ESP_LOGI(TAG, "  [%d] %s (%s) %s",
                                 i, info.hostname, ip_str,
                                 info.direct_path ? "DIRECT" : "DERP");
                    }
                }
            }

            /* Task diagnostics */
            {
                static const char *sn[] = {
                    "Running", "Ready", "Blocked", "Suspended", "Deleted", "Invalid"
                };
                struct { const char *name; TaskHandle_t handle; } tasks[] = {
                    {"net_io",  ml->net_io_task},
                    {"derp_tx", ml->derp_tx_task},
                    {"coord",   ml->coord_task},
                    {"wg_mgr",  ml->wg_mgr_task},
                };
                for (int t = 0; t < 4; t++) {
                    if (tasks[t].handle) {
                        eTaskState st = eTaskGetState(tasks[t].handle);
                        int si = (st <= eInvalid) ? (int)st : 5;
                        ESP_LOGW(TAG, "TASK[%s]: state=%s stack_free=%lu",
                                 tasks[t].name, sn[si],
                                 (unsigned long)uxTaskGetStackHighWaterMark(tasks[t].handle));
                    }
                }
            }
        }
    }
}
