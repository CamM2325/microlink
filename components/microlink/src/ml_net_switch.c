/**
 * @file ml_net_switch.c
 * @brief MicroLink Network Switching — WiFi Primary + Cellular Fallback
 *
 * Full stop/start cycle approach:
 *   1. Try WiFi first (with timeout)
 *   2. If WiFi fails → tear down WiFi, init cellular, start MicroLink over cellular
 *   3. Periodic health check → if VPN drops, trigger switch
 *   4. When on cellular, periodically check if WiFi has recovered → failback
 */

#include "sdkconfig.h"

#ifdef CONFIG_ML_ENABLE_NET_SWITCH

#include "ml_net_switch.h"
#include "ml_cellular.h"
#include "ml_at_socket.h"
#include "ml_config_httpd.h"
#include "ml_at_validate.h"
#include "microlink.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"
#include <string.h>

static const char *TAG = "ml_net_sw";

/* ============================================================================
 * Internal State
 * ========================================================================== */

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
#define NET_SW_STACK_SIZE   6144

/* Defaults for the ml_net_switch_config_t timing fields left at 0
 * (Kconfig "Network Switching"; the fallbacks are the Kconfig defaults). */
#ifndef CONFIG_ML_NET_SWITCH_WIFI_TIMEOUT_MS
#define CONFIG_ML_NET_SWITCH_WIFI_TIMEOUT_MS    30000
#endif
#ifndef CONFIG_ML_NET_SWITCH_HEALTH_INTERVAL_MS
#define CONFIG_ML_NET_SWITCH_HEALTH_INTERVAL_MS 30000
#endif
#ifndef CONFIG_ML_NET_SWITCH_FAILBACK_MS
#define CONFIG_ML_NET_SWITCH_FAILBACK_MS        120000
#endif
#define WIFI_DISCONNECT_DEBOUNCE_MS  5000  /* Wait 5s before declaring WiFi dead */

/* Backoff between full attempts after WiFi and cellular both failed */
#define NET_SW_RETRY_MIN_MS     30000
#define NET_SW_RETRY_MAX_MS     300000

/* How long ml_net_switch_stop() waits for the task to finish its teardown.
 * The task may be inside a modem power-up/registration that cannot be cut
 * short, followed by microlink_stop()'s own join. */
#define NET_SW_STOP_TIMEOUT_MS  300000

/* microlink_stop() attempts (each up to CONFIG_ML_STOP_TIMEOUT_MS) before the
 * handle is destroyed (parked) anyway. The transport must not be torn down
 * under live MicroLink tasks: they would still be using its sockets (and,
 * for PPP, the netif). */
#define VPN_STOP_ATTEMPTS       6

typedef struct {
    /* Config (copied) */
    char wifi_ssid[64];
    char wifi_password[64];
    char sim_pin[16];
    char apn[64];
    char ppp_user[32];
    char ppp_pass[32];
    char tailscale_auth_key[128];
    char device_name[64];

    uint32_t wifi_timeout_ms;
    uint32_t health_check_interval_ms;
    uint32_t health_fail_count;
    uint32_t failback_check_ms;

    /* Callbacks */
    void (*on_connected)(ml_net_type_t type, void *user_data);
    void (*on_disconnected)(void *user_data);
    void (*on_switching)(ml_net_type_t from, ml_net_type_t to, void *user_data);
    void *user_data;

    /* State */
    ml_net_switch_state_t state;
    ml_net_type_t active_transport;
    microlink_t *ml;            /* written only by net_sw task, under s_ml_lock */
    bool initialized;
    volatile bool running;

    /* WiFi */
    EventGroupHandle_t wifi_events;
    int wifi_retry_count;

    /* Health monitoring */
    TimerHandle_t health_timer;
    uint32_t health_fail_counter;

    /* Failback */
    TimerHandle_t failback_timer;

    /* WiFi disconnect debounce */
    TimerHandle_t wifi_debounce_timer;
    bool wifi_disconnect_pending;

    /* Task */
    TaskHandle_t task_handle;
} ml_net_switch_ctx_t;

static ml_net_switch_ctx_t s_ctx = {0};

/* Guards s_ctx.ml against the health timer reading it while the task
 * destroys it. Static storage: no allocation, survives deinit/init. */
static SemaphoreHandle_t s_ml_lock;
static StaticSemaphore_t s_ml_lock_buf;

/* Given by the task as the last thing it does; ml_net_switch_stop() waits
 * on it before declaring the switcher stopped. */
static SemaphoreHandle_t s_task_done;
static StaticSemaphore_t s_task_done_buf;

/* The default WiFi STA netif and the event handler registrations are
 * process-wide and outlive a deinit; keep them so init after deinit works. */
static esp_netif_t *s_wifi_netif;

/* Sleep that returns early (false) once ml_net_switch_stop() was called.
 * Does not consume task notifications. */
static bool sw_sleep(uint32_t ms)
{
    while (ms > 0 && s_ctx.running) {
        uint32_t slice = ms > 250 ? 250 : ms;
        vTaskDelay(pdMS_TO_TICKS(slice));
        ms -= slice;
    }
    return s_ctx.running;
}

/* ============================================================================
 * WiFi Management
 * ========================================================================== */

/* Called 5s after WiFi disconnect if it hasn't reconnected */
static void wifi_debounce_cb(TimerHandle_t timer)
{
    if (!s_ctx.wifi_disconnect_pending) return;
    s_ctx.wifi_disconnect_pending = false;

    /* Only trigger switch if we're on WiFi with VPN up */
    if (s_ctx.active_transport != ML_NET_WIFI) return;
    if (s_ctx.state != ML_NET_SW_WIFI_VPN_UP) return;

    ESP_LOGW(TAG, "WiFi down for %dms — triggering switch to cellular",
             WIFI_DISCONNECT_DEBOUNCE_MS);
    s_ctx.state = ML_NET_SW_SWITCHING_TO_CELL;
    if (s_ctx.task_handle) {
        xTaskNotifyGive(s_ctx.task_handle);
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            if (s_ctx.wifi_retry_count < 5) {
                s_ctx.wifi_retry_count++;
                ESP_LOGI(TAG, "WiFi disconnected, retry %d/5", s_ctx.wifi_retry_count);
                esp_wifi_connect();

                /* Start debounce timer on first disconnect while VPN is up */
                if (s_ctx.wifi_retry_count == 1 &&
                    s_ctx.state == ML_NET_SW_WIFI_VPN_UP &&
                    s_ctx.wifi_debounce_timer) {
                    s_ctx.wifi_disconnect_pending = true;
                    xTimerReset(s_ctx.wifi_debounce_timer, 0);
                }
            } else {
                xEventGroupSetBits(s_ctx.wifi_events, WIFI_FAIL_BIT);
            }
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_ctx.wifi_retry_count = 0;

        /* Cancel debounce — WiFi recovered */
        if (s_ctx.wifi_disconnect_pending) {
            s_ctx.wifi_disconnect_pending = false;
            if (s_ctx.wifi_debounce_timer) {
                xTimerStop(s_ctx.wifi_debounce_timer, 0);
            }
            ESP_LOGI(TAG, "WiFi recovered within debounce window");
        }

        xEventGroupSetBits(s_ctx.wifi_events, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_start(void)
{
    ESP_LOGI(TAG, "Starting WiFi (%s)...", s_ctx.wifi_ssid);

    s_ctx.wifi_retry_count = 0;
    xEventGroupClearBits(s_ctx.wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    if (!s_wifi_netif) {
        s_wifi_netif = esp_netif_create_default_wifi_sta();
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(
            WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, NULL));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(
            IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, NULL));
    }

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, s_ctx.wifi_ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, s_ctx.wifi_password, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    /* Wait for connection (in slices, so a stop request is noticed) */
    EventBits_t bits = 0;
    for (uint32_t waited = 0; waited < s_ctx.wifi_timeout_ms && s_ctx.running; waited += 250) {
        bits = xEventGroupWaitBits(s_ctx.wifi_events,
                                   WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                   pdFALSE, pdFALSE, pdMS_TO_TICKS(250));
        if (bits & (WIFI_CONNECTED_BIT | WIFI_FAIL_BIT)) break;
    }

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected");
        return ESP_OK;
    }

    ESP_LOGW(TAG, "WiFi connection failed (timeout=%lums)", (unsigned long)s_ctx.wifi_timeout_ms);
    return ESP_ERR_TIMEOUT;
}

static void wifi_stop(void)
{
    ESP_LOGI(TAG, "Stopping WiFi...");
    esp_wifi_disconnect();
    esp_wifi_stop();
}

/* ============================================================================
 * Cellular Management
 * ========================================================================== */

static esp_err_t cellular_start(void)
{
    /* A rejected SIM PIN is never retried (it would PUK-lock the SIM), so
     * powering the modem up again is pointless until reboot. */
    if (ml_cellular_sim_pin_blocked()) {
        static bool logged;
        if (!logged) {
            ESP_LOGE(TAG, "Cellular disabled until reboot: SIM PIN rejected or attempts "
                     "nearly used up (fix CONFIG_ML_CELLULAR_SIM_PIN)");
            logged = true;
        }
        return ESP_ERR_NOT_ALLOWED;
    }

    ESP_LOGI(TAG, "Starting cellular modem...");

    ml_cellular_config_t cell_config = {
        .tx_pin = CONFIG_ML_CELLULAR_TX_PIN,
        .rx_pin = CONFIG_ML_CELLULAR_RX_PIN,
        .baud_rate = 115200,
        .apn = s_ctx.apn[0] ? s_ctx.apn : NULL,
        .sim_pin = s_ctx.sim_pin[0] ? s_ctx.sim_pin : NULL,
    };

    /* Apply APN: NVS (web UI) > config struct > Kconfig.
     * ml_cellular_init() copies the strings, so these can be locals. */
    char nvs_apn[ML_AT_APN_MAX + 1] = "";
    if (ml_config_get_nvs_apn(nvs_apn, sizeof(nvs_apn))) {
        cell_config.apn = nvs_apn;
    }

    /* Apply PPP credentials: NVS (web UI) > Kconfig */
    char nvs_ppp_user[ML_AT_CRED_MAX + 1] = "", nvs_ppp_pass[ML_AT_CRED_MAX + 1] = "";
    if (ml_config_get_nvs_ppp(nvs_ppp_user, sizeof(nvs_ppp_user),
                               nvs_ppp_pass, sizeof(nvs_ppp_pass))) {
        cell_config.ppp_user = nvs_ppp_user;
        cell_config.ppp_pass = nvs_ppp_pass;
    } else {
        const char *ppp_u = CONFIG_ML_CELLULAR_PPP_USER;
        if (ppp_u && ppp_u[0]) cell_config.ppp_user = ppp_u;
        const char *ppp_p = CONFIG_ML_CELLULAR_PPP_PASS;
        if (ppp_p && ppp_p[0]) cell_config.ppp_pass = ppp_p;
    }

    esp_err_t err = ml_cellular_init(&cell_config);
    ml_at_secure_zero(nvs_ppp_user, sizeof(nvs_ppp_user));
    ml_at_secure_zero(nvs_ppp_pass, sizeof(nvs_ppp_pass));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cellular init failed: %s", esp_err_to_name(err));
        return err;
    }

    err = ml_cellular_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cellular data connection failed: %s", esp_err_to_name(err));
        ml_cellular_deinit();
        return err;
    }

    ml_cellular_data_mode_t mode = ml_cellular_get_data_mode();
    ESP_LOGI(TAG, "Cellular connected via %s",
             mode == ML_DATA_MODE_PPP ? "PPP" : "AT socket bridge");
    return ESP_OK;
}

static void cellular_stop(void)
{
    ESP_LOGI(TAG, "Stopping cellular...");
    ml_cellular_data_stop();
    ml_cellular_deinit();
}

/* ============================================================================
 * MicroLink VPN Management
 * ========================================================================== */

/* Unpublish the handle, then stop and destroy it. Only the net_sw task
 * calls this, so the handle cannot be destroyed twice. */
static void vpn_stop(void)
{
    xSemaphoreTake(s_ml_lock, portMAX_DELAY);
    microlink_t *ml = s_ctx.ml;
    s_ctx.ml = NULL;
    xSemaphoreGive(s_ml_lock);
    if (!ml) return;

    /* microlink_stop() returns ESP_ERR_TIMEOUT while a task is still stuck
     * in a network call; keep waiting so the caller does not tear down the
     * transport under it. */
    for (int i = 0; i < VPN_STOP_ATTEMPTS; i++) {
        if (microlink_stop(ml) != ESP_ERR_TIMEOUT) break;
        ESP_LOGW(TAG, "MicroLink tasks still exiting (attempt %d/%d)", i + 1, VPN_STOP_ATTEMPTS);
    }
    /* Frees the handle, or parks it if a task is still running. */
    microlink_destroy(ml);
}

static esp_err_t vpn_start(void)
{
    const char *name = s_ctx.device_name[0] ? s_ctx.device_name : NULL;

    /* For cellular, prefer IMEI-based name */
    if (s_ctx.active_transport == ML_NET_CELLULAR && !name) {
        name = microlink_imei_device_name();
    }
    if (!name) {
        name = microlink_default_device_name();
    }

    microlink_config_t ml_config = {
        .auth_key = s_ctx.tailscale_auth_key,
        .device_name = name,
        .enable_derp = true,
        .enable_stun = (s_ctx.active_transport == ML_NET_WIFI),
        .enable_disco = true,
        .max_peers = CONFIG_ML_MAX_PEERS,
    };

    microlink_t *ml = microlink_init(&ml_config);
    if (!ml) {
        ESP_LOGE(TAG, "microlink_init failed");
        return ESP_FAIL;
    }
    xSemaphoreTake(s_ml_lock, portMAX_DELAY);
    s_ctx.ml = ml;
    xSemaphoreGive(s_ml_lock);

    esp_err_t err = microlink_start(ml);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "microlink_start failed: %s", esp_err_to_name(err));
        vpn_stop();
        return err;
    }

    /* Wait for connection — large tailnets (200+ peers) over cellular can take
     * 3-4 minutes to download the full MapResponse via AT socket bridge.
     * Use 180s for cellular, 60s for WiFi. */
    int timeout_ticks = (s_ctx.active_transport == ML_NET_WIFI) ? 120 : 360;
    int timeout_secs = timeout_ticks / 2;
    for (int i = 0; i < timeout_ticks; i++) {
        if (!s_ctx.running) {
            ESP_LOGI(TAG, "Stop requested while waiting for the VPN");
            vpn_stop();
            return ESP_ERR_INVALID_STATE;
        }
        if (microlink_is_connected(ml)) {
            uint32_t ip = microlink_get_vpn_ip(ml);
            char ip_str[16];
            microlink_ip_to_str(ip, ip_str);
            ESP_LOGI(TAG, "VPN connected via %s (IP: %s)",
                     s_ctx.active_transport == ML_NET_WIFI ? "WiFi" : "Cellular",
                     ip_str);
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    /* Typically coord is still mid-MapResponse here; vpn_stop() joins it
     * (microlink_stop() unblocks its socket) before destroying the handle. */
    ESP_LOGW(TAG, "VPN connection timeout (%ds)", timeout_secs);
    vpn_stop();
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * Health Check Timer
 * ========================================================================== */

static void health_timer_cb(TimerHandle_t timer)
{
    if (!s_ctx.running) return;

    /* Timer task: never block. If the switch task holds the lock it is
     * replacing the handle; skip this round. */
    if (xSemaphoreTake(s_ml_lock, 0) != pdTRUE) return;
    bool have_ml = (s_ctx.ml != NULL);
    bool connected = have_ml && microlink_is_connected(s_ctx.ml);
    xSemaphoreGive(s_ml_lock);
    if (!have_ml) return;

    if (!connected) {
        s_ctx.health_fail_counter++;
        ESP_LOGW(TAG, "Health check failed (%lu/%lu)",
                 (unsigned long)s_ctx.health_fail_counter,
                 (unsigned long)s_ctx.health_fail_count);

        if (s_ctx.health_fail_counter >= s_ctx.health_fail_count) {
            ESP_LOGE(TAG, "Health check threshold reached — triggering network switch");
            s_ctx.health_fail_counter = 0;

            if (s_ctx.active_transport == ML_NET_WIFI) {
                s_ctx.state = ML_NET_SW_SWITCHING_TO_CELL;
            } else {
                s_ctx.state = ML_NET_SW_SWITCHING_TO_WIFI;
            }

            /* Wake the task */
            if (s_ctx.task_handle) {
                xTaskNotifyGive(s_ctx.task_handle);
            }
        }
    } else {
        s_ctx.health_fail_counter = 0;
    }
}

/* ============================================================================
 * Failback Timer (check if WiFi recovered while on cellular)
 * ========================================================================== */

static void failback_timer_cb(TimerHandle_t timer)
{
    if (!s_ctx.running) return;
    if (s_ctx.active_transport != ML_NET_CELLULAR) return;

    /* Don't attempt failback if no WiFi credentials configured */
    if (s_ctx.wifi_ssid[0] == '\0') return;

    ESP_LOGI(TAG, "Failback check: attempting WiFi reconnection...");
    s_ctx.state = ML_NET_SW_SWITCHING_TO_WIFI;

    if (s_ctx.task_handle) {
        xTaskNotifyGive(s_ctx.task_handle);
    }
}

/* ============================================================================
 * Main State Machine Task
 * ========================================================================== */

/* Bring the VPN up over WiFi. On failure WiFi is stopped again. */
static bool try_wifi(void)
{
    s_ctx.state = ML_NET_SW_WIFI_CONNECTING;
    s_ctx.active_transport = ML_NET_WIFI;

    if (wifi_start() == ESP_OK && vpn_start() == ESP_OK) {
        s_ctx.state = ML_NET_SW_WIFI_VPN_UP;
        if (s_ctx.on_connected) {
            s_ctx.on_connected(ML_NET_WIFI, s_ctx.user_data);
        }
        xTimerStart(s_ctx.health_timer, 0);
        return true;
    }

    if (s_ctx.running) {
        ESP_LOGW(TAG, "WiFi path failed, falling back to cellular");
    }
    wifi_stop();
    return false;
}

/* Bring the VPN up over cellular. Cellular is left as is on failure; the
 * caller stops it before the next attempt. */
static bool try_cellular(void)
{
    /* The failback timer would flip the state to SWITCHING_TO_WIFI while
     * this attempt is still running. */
    xTimerStop(s_ctx.health_timer, 0);
    if (s_ctx.failback_timer) xTimerStop(s_ctx.failback_timer, 0);

    s_ctx.state = ML_NET_SW_CELL_CONNECTING;
    s_ctx.active_transport = ML_NET_CELLULAR;

    if (s_ctx.on_switching) {
        s_ctx.on_switching(ML_NET_WIFI, ML_NET_CELLULAR, s_ctx.user_data);
    }

    if (cellular_start() == ESP_OK && s_ctx.running && vpn_start() == ESP_OK) {
        s_ctx.state = ML_NET_SW_CELL_VPN_UP;
        if (s_ctx.on_connected) {
            s_ctx.on_connected(ML_NET_CELLULAR, s_ctx.user_data);
        }
        /* Start health check + failback timers */
        xTimerStart(s_ctx.health_timer, 0);
        if (s_ctx.failback_check_ms > 0 && s_ctx.failback_timer) {
            xTimerStart(s_ctx.failback_timer, 0);
        }
        return true;
    }
    return false;
}

typedef enum {
    SW_LOOP_STOPPED,        /* ml_net_switch_stop() was called */
    SW_LOOP_RETRY_CELL,     /* VPN lost and could not be moved; restart on cellular */
} sw_loop_result_t;

/* Runs while the VPN is up: reacts to the health/failback/debounce timers. */
static sw_loop_result_t state_loop(void)
{
    while (s_ctx.running) {
        /* Wait for notification from health/failback timer */
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(5000));

        if (!s_ctx.running) break;

        switch (s_ctx.state) {
            case ML_NET_SW_SWITCHING_TO_CELL: {
                ESP_LOGI(TAG, "Switching WiFi → Cellular");
                xTimerStop(s_ctx.health_timer, 0);

                if (s_ctx.on_switching) {
                    s_ctx.on_switching(ML_NET_WIFI, ML_NET_CELLULAR, s_ctx.user_data);
                }

                /* Start cellular while WiFi VPN is still running */
                s_ctx.state = ML_NET_SW_CELL_CONNECTING;
                esp_err_t cell_err = cellular_start();
                if (cell_err == ESP_OK) {
                    /* Cellular is up — rebind sockets instead of full restart */
                    wifi_stop();
                    s_ctx.active_transport = ML_NET_CELLULAR;
                    esp_err_t rb_err = microlink_rebind(s_ctx.ml);
                    if (rb_err == ESP_OK) {
                        ESP_LOGI(TAG, "Rebind to cellular complete");
                        s_ctx.state = ML_NET_SW_CELL_VPN_UP;
                        if (s_ctx.on_connected) {
                            s_ctx.on_connected(ML_NET_CELLULAR, s_ctx.user_data);
                        }
                        xTimerStart(s_ctx.health_timer, 0);
                        if (s_ctx.failback_check_ms > 0 && s_ctx.failback_timer) {
                            xTimerStart(s_ctx.failback_timer, 0);
                        }
                    } else {
                        ESP_LOGE(TAG, "Rebind failed (%s), full restart",
                                 esp_err_to_name(rb_err));
                        vpn_stop();
                        wifi_stop();
                        /* try_cellular() initializes the modem itself */
                        cellular_stop();
                        return SW_LOOP_RETRY_CELL;
                    }
                } else {
                    /* Cellular failed — full restart path */
                    ESP_LOGE(TAG, "Cellular start failed, full restart");
                    if (s_ctx.on_disconnected) {
                        s_ctx.on_disconnected(s_ctx.user_data);
                    }
                    vpn_stop();
                    wifi_stop();
                    return SW_LOOP_RETRY_CELL;
                }
                break;
            }

            case ML_NET_SW_SWITCHING_TO_WIFI: {
                ESP_LOGI(TAG, "Attempting failback: Cellular → WiFi");
                xTimerStop(s_ctx.health_timer, 0);
                if (s_ctx.failback_timer) {
                    xTimerStop(s_ctx.failback_timer, 0);
                }

                /* Try WiFi without tearing down cellular yet */
                s_ctx.state = ML_NET_SW_WIFI_CONNECTING;

                esp_err_t wifi_err = wifi_start();
                if (!s_ctx.running) break;
                if (wifi_err == ESP_OK) {
                    /* WiFi is back — rebind sockets to WiFi interface */
                    ESP_LOGI(TAG, "WiFi recovered! Rebinding to WiFi");

                    if (s_ctx.on_switching) {
                        s_ctx.on_switching(ML_NET_CELLULAR, ML_NET_WIFI, s_ctx.user_data);
                    }

                    /* Tear down cellular transport first so ml_at_socket_is_ready()
                     * returns false and ml_* wrappers route to BSD sockets */
                    cellular_stop();
                    s_ctx.active_transport = ML_NET_WIFI;

                    esp_err_t rb_err = microlink_rebind(s_ctx.ml);
                    if (rb_err == ESP_OK) {
                        ESP_LOGI(TAG, "Rebind to WiFi complete");
                        s_ctx.state = ML_NET_SW_WIFI_VPN_UP;
                        if (s_ctx.on_connected) {
                            s_ctx.on_connected(ML_NET_WIFI, s_ctx.user_data);
                        }
                        xTimerStart(s_ctx.health_timer, 0);
                    } else {
                        /* Rebind failed — try full restart on cellular */
                        ESP_LOGW(TAG, "Rebind to WiFi failed (%s), reverting to cellular",
                                 esp_err_to_name(rb_err));
                        wifi_stop();
                        vpn_stop();
                        return SW_LOOP_RETRY_CELL;
                    }
                } else {
                    /* WiFi still down, stay on cellular */
                    ESP_LOGI(TAG, "WiFi still unavailable, staying on cellular");
                    wifi_stop();
                    s_ctx.state = ML_NET_SW_CELL_VPN_UP;
                    xTimerStart(s_ctx.health_timer, 0);
                    if (s_ctx.failback_check_ms > 0 && s_ctx.failback_timer) {
                        xTimerStart(s_ctx.failback_timer, 0);
                    }
                }
                break;
            }

            default:
                break;
        }
    }
    return SW_LOOP_STOPPED;
}

static void net_switch_task(void *arg)
{
    ESP_LOGI(TAG, "Network switch task started");

    bool has_wifi = (s_ctx.wifi_ssid[0] != '\0');
    bool cellular_only_next = false;
    uint32_t retry_ms = NET_SW_RETRY_MIN_MS;

    /* Every failure path comes back here, so a transient double failure is
     * retried (with backoff) instead of leaving the device offline until a
     * reboot. */
    while (s_ctx.running) {
        bool up = false;

        if (!has_wifi) {
            ESP_LOGI(TAG, "No WiFi SSID configured, going straight to cellular");
        } else if (!cellular_only_next) {
            up = try_wifi();
        }
        cellular_only_next = false;

        if (!up && s_ctx.running) {
            up = try_cellular();
        }

        if (up) {
            retry_ms = NET_SW_RETRY_MIN_MS;
            if (state_loop() == SW_LOOP_RETRY_CELL) {
                cellular_only_next = true;
            }
            continue;
        }

        if (!s_ctx.running) break;

        ESP_LOGE(TAG, "Both WiFi and cellular failed! Retrying in %lus",
                 (unsigned long)(retry_ms / 1000));
        s_ctx.state = ML_NET_SW_ERROR;
        if (s_ctx.on_disconnected) {
            s_ctx.on_disconnected(s_ctx.user_data);
        }

        sw_sleep(retry_ms);
        retry_ms = (retry_ms * 2 > NET_SW_RETRY_MAX_MS) ? NET_SW_RETRY_MAX_MS : retry_ms * 2;
        cellular_stop();
    }

    /* Teardown, in this task, which owns the handle and the transports.
     * MicroLink first: it must be joined before its transport goes away. */
    ESP_LOGI(TAG, "Network switch task stopping");
    xTimerStop(s_ctx.health_timer, 0);
    if (s_ctx.failback_timer) xTimerStop(s_ctx.failback_timer, 0);
    vpn_stop();
    if (has_wifi) wifi_stop();
    cellular_stop();
    s_ctx.state = ML_NET_SW_IDLE;

    ESP_LOGI(TAG, "Network switch task exiting");
    s_ctx.task_handle = NULL;
    xSemaphoreGive(s_task_done);
    vTaskDelete(NULL);
}

/* ============================================================================
 * Public API
 * ========================================================================== */

esp_err_t ml_net_switch_init(const ml_net_switch_config_t *config)
{
    if (s_ctx.initialized) return ESP_ERR_INVALID_STATE;
    if (!config || !config->tailscale_auth_key) return ESP_ERR_INVALID_ARG;

    /* Cellular values are only used when WiFi fails; check them now so a
     * bad value (they go into modem AT commands) fails loudly at startup
     * instead of silently breaking failover later. */
    if (config->apn && !ml_at_param_valid(ML_AT_PARAM_APN, config->apn, sizeof(s_ctx.apn) - 1)) {
        ESP_LOGE(TAG, "Invalid APN: letters, digits, '-' and '.' only (max %u)",
                 (unsigned)(sizeof(s_ctx.apn) - 1));
        return ESP_ERR_INVALID_ARG;
    }
    if (config->sim_pin && config->sim_pin[0] && !ml_at_valid_pin(config->sim_pin)) {
        ESP_LOGE(TAG, "Invalid SIM PIN: must be 4-8 digits");
        return ESP_ERR_INVALID_ARG;
    }
    if (!ml_at_valid_credential(CONFIG_ML_CELLULAR_PPP_USER) ||
        !ml_at_valid_credential(CONFIG_ML_CELLULAR_PPP_PASS)) {
        ESP_LOGE(TAG, "Invalid CONFIG_ML_CELLULAR_PPP_USER/PASS: printable ASCII "
                 "without '\"' or '\\', max %d", ML_AT_CRED_MAX);
        return ESP_ERR_INVALID_ARG;
    }

    memset(&s_ctx, 0, sizeof(s_ctx));

    if (!s_ml_lock) s_ml_lock = xSemaphoreCreateMutexStatic(&s_ml_lock_buf);
    if (!s_task_done) s_task_done = xSemaphoreCreateBinaryStatic(&s_task_done_buf);

    /* Copy strings */
    if (config->wifi_ssid) strncpy(s_ctx.wifi_ssid, config->wifi_ssid, sizeof(s_ctx.wifi_ssid) - 1);
    if (config->wifi_password) strncpy(s_ctx.wifi_password, config->wifi_password, sizeof(s_ctx.wifi_password) - 1);
    if (config->sim_pin) strncpy(s_ctx.sim_pin, config->sim_pin, sizeof(s_ctx.sim_pin) - 1);
    if (config->apn) strncpy(s_ctx.apn, config->apn, sizeof(s_ctx.apn) - 1);
    strncpy(s_ctx.tailscale_auth_key, config->tailscale_auth_key, sizeof(s_ctx.tailscale_auth_key) - 1);
    if (config->device_name) strncpy(s_ctx.device_name, config->device_name, sizeof(s_ctx.device_name) - 1);

    /* Timing defaults */
    s_ctx.wifi_timeout_ms = config->wifi_timeout_ms ? config->wifi_timeout_ms
                                                    : CONFIG_ML_NET_SWITCH_WIFI_TIMEOUT_MS;
    s_ctx.health_check_interval_ms = config->health_check_interval_ms ? config->health_check_interval_ms
                                                                      : CONFIG_ML_NET_SWITCH_HEALTH_INTERVAL_MS;
    s_ctx.health_fail_count = config->health_fail_count ? config->health_fail_count : 3;
    s_ctx.failback_check_ms = config->failback_check_ms ? config->failback_check_ms
                                                        : CONFIG_ML_NET_SWITCH_FAILBACK_MS;

    /* Callbacks */
    s_ctx.on_connected = config->on_connected;
    s_ctx.on_disconnected = config->on_disconnected;
    s_ctx.on_switching = config->on_switching;
    s_ctx.user_data = config->user_data;

    /* Create event group for WiFi */
    s_ctx.wifi_events = xEventGroupCreate();
    if (!s_ctx.wifi_events) return ESP_ERR_NO_MEM;

    /* Create health check timer */
    s_ctx.health_timer = xTimerCreate("net_health",
                                       pdMS_TO_TICKS(s_ctx.health_check_interval_ms),
                                       pdTRUE, NULL, health_timer_cb);
    if (!s_ctx.health_timer) return ESP_ERR_NO_MEM;

    /* Create failback timer */
    if (s_ctx.failback_check_ms > 0) {
        s_ctx.failback_timer = xTimerCreate("net_failback",
                                             pdMS_TO_TICKS(s_ctx.failback_check_ms),
                                             pdTRUE, NULL, failback_timer_cb);
    }

    /* Create WiFi disconnect debounce timer (one-shot) */
    s_ctx.wifi_debounce_timer = xTimerCreate("wifi_debounce",
                                              pdMS_TO_TICKS(WIFI_DISCONNECT_DEBOUNCE_MS),
                                              pdFALSE, NULL, wifi_debounce_cb);

    s_ctx.state = ML_NET_SW_IDLE;
    s_ctx.initialized = true;

    ESP_LOGI(TAG, "Net switch initialized (wifi_timeout=%lums, health=%lums, failback=%lums)",
             (unsigned long)s_ctx.wifi_timeout_ms,
             (unsigned long)s_ctx.health_check_interval_ms,
             (unsigned long)s_ctx.failback_check_ms);

    return ESP_OK;
}

void ml_net_switch_deinit(void)
{
    if (!s_ctx.initialized) return;

    if (ml_net_switch_stop() != ESP_OK) {
        /* The task is still running and uses the timers, the event group
         * and s_ctx; freeing them now would be a use-after-free. */
        ESP_LOGE(TAG, "Deinit skipped: network switch task has not exited");
        return;
    }

    if (s_ctx.health_timer) {
        xTimerDelete(s_ctx.health_timer, portMAX_DELAY);
    }
    if (s_ctx.failback_timer) {
        xTimerDelete(s_ctx.failback_timer, portMAX_DELAY);
    }
    if (s_ctx.wifi_debounce_timer) {
        xTimerDelete(s_ctx.wifi_debounce_timer, portMAX_DELAY);
    }
    if (s_ctx.wifi_events) {
        vEventGroupDelete(s_ctx.wifi_events);
    }

    memset(&s_ctx, 0, sizeof(s_ctx));
}

esp_err_t ml_net_switch_start(void)
{
    if (!s_ctx.initialized) return ESP_ERR_INVALID_STATE;
    if (s_ctx.running || s_ctx.task_handle) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_task_done, 0);  /* clear a stale completion */
    s_ctx.running = true;

    BaseType_t ret = xTaskCreate(net_switch_task, "net_sw",
                                  NET_SW_STACK_SIZE, NULL, 5, &s_ctx.task_handle);
    if (ret != pdPASS) {
        s_ctx.running = false;
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t ml_net_switch_stop(void)
{
    if (!s_ctx.running && !s_ctx.task_handle) return ESP_OK;

    if (s_ctx.task_handle && xTaskGetCurrentTaskHandle() == s_ctx.task_handle) {
        /* From an on_* callback: the task cannot wait for itself. */
        ESP_LOGE(TAG, "ml_net_switch_stop() called from the switch task (callback?)");
        return ESP_ERR_INVALID_STATE;
    }

    s_ctx.running = false;

    /* Stop timers */
    if (s_ctx.health_timer) xTimerStop(s_ctx.health_timer, portMAX_DELAY);
    if (s_ctx.failback_timer) xTimerStop(s_ctx.failback_timer, portMAX_DELAY);
    if (s_ctx.wifi_debounce_timer) xTimerStop(s_ctx.wifi_debounce_timer, portMAX_DELAY);
    s_ctx.wifi_disconnect_pending = false;

    /* The task owns the MicroLink handle and the transports and tears them
     * down itself on the way out. Tearing them down here as well raced with
     * it (double microlink_destroy, use of a freed handle). Wait for it. */
    TaskHandle_t task = s_ctx.task_handle;
    if (task) {
        xTaskNotifyGive(task);
    }
    if (xSemaphoreTake(s_task_done, pdMS_TO_TICKS(NET_SW_STOP_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "Network switch task did not exit within %ds",
                 NET_SW_STOP_TIMEOUT_MS / 1000);
        return ESP_ERR_TIMEOUT;
    }

    s_ctx.state = ML_NET_SW_IDLE;
    return ESP_OK;
}

ml_net_type_t ml_net_switch_get_active(void)
{
    return s_ctx.active_transport;
}

ml_net_switch_state_t ml_net_switch_get_state(void)
{
    return s_ctx.state;
}

microlink_t *ml_net_switch_get_handle(void)
{
    if (!s_ml_lock) return NULL;
    xSemaphoreTake(s_ml_lock, portMAX_DELAY);
    microlink_t *ml = s_ctx.ml;
    xSemaphoreGive(s_ml_lock);
    return ml;
}

const char *ml_net_switch_state_str(ml_net_switch_state_t state)
{
    switch (state) {
        case ML_NET_SW_IDLE:              return "IDLE";
        case ML_NET_SW_WIFI_CONNECTING:   return "WIFI_CONNECTING";
        case ML_NET_SW_WIFI_VPN_UP:       return "WIFI_VPN_UP";
        case ML_NET_SW_SWITCHING_TO_CELL: return "SWITCHING_TO_CELL";
        case ML_NET_SW_CELL_CONNECTING:   return "CELL_CONNECTING";
        case ML_NET_SW_CELL_VPN_UP:       return "CELL_VPN_UP";
        case ML_NET_SW_SWITCHING_TO_WIFI: return "SWITCHING_TO_WIFI";
        case ML_NET_SW_ERROR:             return "ERROR";
        default:                          return "UNKNOWN";
    }
}

#endif /* CONFIG_ML_ENABLE_NET_SWITCH */
