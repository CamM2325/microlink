/**
 * @file main.c
 * @brief microlink_rebind() Integration Test — Full Switching
 *
 * Tests three rebind scenarios:
 *   Test 1: Same-interface rebind (PPP → PPP)
 *   Test 2: Cellular → WiFi rebind
 *   Test 3: WiFi → Cellular rebind
 *
 * WiFi credentials loaded from NVS (set via web config UI).
 * If no WiFi creds in NVS, only Test 1 runs.
 */

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#include "microlink.h"
#include "microlink_internal.h"
#include "ml_cellular.h"
#include "ml_config_httpd.h"

static const char *TAG = "rebind_test";

static microlink_t *ml = NULL;

#define REBIND_DELAY_S     15
#define RECOVERY_TIMEOUT_S 30
#define WIFI_CONNECT_TIMEOUT_MS 15000

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static EventGroupHandle_t s_wifi_events;
static esp_netif_t *s_wifi_netif = NULL;
static int s_wifi_retries = 0;

/* WiFi credentials from NVS */
static char wifi_ssid[33] = "";
static char wifi_pass[65] = "";

static void on_state_change(microlink_t *handle, microlink_state_t state, void *user_data) {
    const char *names[] = {
        "IDLE", "WIFI_WAIT", "CONNECTING", "REGISTERING",
        "CONNECTED", "RECONNECTING", "ERROR"
    };
    const char *name = (state < sizeof(names)/sizeof(names[0])) ? names[state] : "UNKNOWN";
    ESP_LOGI(TAG, "State: %s", name);
}

/* ============================================================================
 * WiFi helpers
 * ========================================================================== */

static void wifi_event_handler(void *arg, esp_event_base_t base,
                                int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_wifi_retries < 3) {
            s_wifi_retries++;
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "WiFi connected: " IPSTR, IP2STR(&event->ip_info.ip));
        s_wifi_retries = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_start(void)
{
    ESP_LOGI(TAG, "Connecting WiFi: %s", wifi_ssid);
    s_wifi_retries = 0;
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

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
    strncpy((char *)wifi_config.sta.ssid, wifi_ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, wifi_pass, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE,
        pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS));

    if (bits & WIFI_CONNECTED_BIT) return ESP_OK;
    ESP_LOGW(TAG, "WiFi connection failed");
    return ESP_ERR_TIMEOUT;
}

static void wifi_stop(void)
{
    esp_wifi_disconnect();
    esp_wifi_stop();
}

/* ============================================================================
 * Rebind helper — returns true on pass
 * ========================================================================== */

static bool do_rebind_test(const char *label)
{
    ESP_LOGW(TAG, "============================================");
    ESP_LOGW(TAG, "=== %s ===", label);
    ESP_LOGW(TAG, "============================================");

    int pre_sock = ml->disco_sock4;

    uint64_t t0 = xTaskGetTickCount();
    esp_err_t ret = microlink_rebind(ml);
    uint32_t rebind_ms = (xTaskGetTickCount() - t0) * portTICK_PERIOD_MS;

    ESP_LOGI(TAG, "microlink_rebind() returned %s in %lu ms",
             esp_err_to_name(ret), (unsigned long)rebind_ms);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "FAIL: rebind returned %s", esp_err_to_name(ret));
        return false;
    }

    ESP_LOGI(TAG, "POST: disco_sock4=%d port=%u", ml->disco_sock4, ml->disco_local_port);

    if (ml->disco_sock4 < 0) {
        ESP_LOGE(TAG, "FAIL: disco_sock4 not recreated");
        return false;
    }

    /* Wait for VPN recovery */
    bool recovered = false;
    bool saw_disconnect = false;
    uint64_t recovery_start = xTaskGetTickCount();

    for (int i = 0; i < RECOVERY_TIMEOUT_S * 2; i++) {
        vTaskDelay(pdMS_TO_TICKS(500));
        bool connected = microlink_is_connected(ml);
        if (!connected && !saw_disconnect) {
            saw_disconnect = true;
            ESP_LOGW(TAG, "  VPN disconnected (expected)");
        }
        if (connected) {
            uint32_t recovery_ms = (xTaskGetTickCount() - recovery_start) * portTICK_PERIOD_MS;
            ESP_LOGI(TAG, "VPN recovered in %lu ms (disconnect=%s)",
                     (unsigned long)recovery_ms, saw_disconnect ? "yes" : "no");
            recovered = true;
            break;
        }
        if (i % 10 == 0) ESP_LOGI(TAG, "  Waiting... %ds", i / 2);
    }

    printf("\n  %s: rebind=%lums sock=%d->%d recovery=%s\n\n",
           label, (unsigned long)rebind_ms, pre_sock, ml->disco_sock4,
           recovered ? "PASS" : "FAIL");

    return recovered;
}

/* ============================================================================
 * Main
 * ========================================================================== */

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_wifi_events = xEventGroupCreate();

    /* Load WiFi creds from NVS (set via web config UI) */
    bool has_wifi = ml_config_get_nvs_wifi(wifi_ssid, sizeof(wifi_ssid),
                                            wifi_pass, sizeof(wifi_pass));

    printf("\n");
    printf("================================================================\n");
    printf("  microlink_rebind() Full Switching Test\n");
    printf("  WiFi: %s\n", has_wifi ? wifi_ssid : "(none — NVS empty, skip WiFi tests)");
    printf("================================================================\n\n");

    /* Step 1: Cellular init + PPP */
    ESP_LOGI(TAG, "=== Step 1: Cellular init ===");

    ml_cellular_config_t cell_config = ML_CELLULAR_DEFAULT_CONFIG();
    cell_config.tx_pin = CONFIG_ML_CELLULAR_TX_PIN;
    cell_config.rx_pin = CONFIG_ML_CELLULAR_RX_PIN;

    const char *apn = CONFIG_ML_CELLULAR_APN;
    if (apn && apn[0]) cell_config.apn = apn;
    const char *ppp_user = CONFIG_ML_CELLULAR_PPP_USER;
    if (ppp_user && ppp_user[0]) cell_config.ppp_user = ppp_user;
    const char *ppp_pass = CONFIG_ML_CELLULAR_PPP_PASS;
    if (ppp_pass && ppp_pass[0]) cell_config.ppp_pass = ppp_pass;

    static char nvs_apn[32] = "";
    if (ml_config_get_nvs_apn(nvs_apn, sizeof(nvs_apn))) {
        cell_config.apn = nvs_apn;
    }
    static char nvs_ppp_user[32] = "", nvs_ppp_pass[32] = "";
    if (ml_config_get_nvs_ppp(nvs_ppp_user, sizeof(nvs_ppp_user),
                               nvs_ppp_pass, sizeof(nvs_ppp_pass))) {
        cell_config.ppp_user = nvs_ppp_user;
        cell_config.ppp_pass = nvs_ppp_pass;
    }

    ret = ml_cellular_init(&cell_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "FAIL: Cellular init: %s", esp_err_to_name(ret));
        return;
    }

    ESP_LOGI(TAG, "=== Step 2: PPP connect ===");
    ret = ml_cellular_connect();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "FAIL: Cellular data: %s", esp_err_to_name(ret));
        return;
    }
    ESP_LOGI(TAG, "Data mode: %s",
             ml_cellular_get_data_mode() == ML_DATA_MODE_PPP ? "PPP" : "AT socket");

    /* Step 3: Start MicroLink */
    ESP_LOGI(TAG, "=== Step 3: MicroLink start ===");

    const char *device_name = microlink_imei_device_name();
    if (!device_name || !device_name[0]) device_name = microlink_default_device_name();

    microlink_config_t config = {
        .auth_key = CONFIG_ML_TAILSCALE_AUTH_KEY,
        .device_name = device_name,
        .enable_derp = true,
        .enable_stun = true,
        .enable_disco = true,
        .max_peers = CONFIG_ML_MAX_PEERS,
    };

    ml = microlink_init(&config);
    if (!ml) { ESP_LOGE(TAG, "FAIL: microlink_init"); return; }
    microlink_set_state_callback(ml, on_state_change, NULL);
    ESP_ERROR_CHECK(microlink_start(ml));

    ESP_LOGI(TAG, "Waiting for CONNECTED...");
    int wait_s = 0;
    while (!microlink_is_connected(ml)) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (++wait_s > 120) {
            ESP_LOGE(TAG, "FAIL: Timed out (120s)");
            return;
        }
    }

    uint32_t vpn_ip = microlink_get_vpn_ip(ml);
    char ip_str[16];
    microlink_ip_to_str(vpn_ip, ip_str);
    ESP_LOGI(TAG, "CONNECTED: %s (%d peers) in %ds",
             ip_str, microlink_get_peer_count(ml), wait_s);

    /* ================================================================
     * Test 1: Same-interface rebind (PPP → PPP)
     * ================================================================ */
    ESP_LOGI(TAG, "=== Stabilizing %ds before Test 1... ===", REBIND_DELAY_S);
    vTaskDelay(pdMS_TO_TICKS(REBIND_DELAY_S * 1000));

    bool test1 = do_rebind_test("TEST 1: Same-interface (PPP->PPP)");

    /* Stabilize after test 1 */
    ESP_LOGI(TAG, "Stabilizing 15s...");
    vTaskDelay(pdMS_TO_TICKS(15000));

    /* ================================================================
     * Test 2: Cellular → WiFi rebind
     * ================================================================ */
    bool test2 = false;
    bool test3 = false;

    if (!has_wifi) {
        ESP_LOGW(TAG, "No WiFi creds in NVS — skipping Tests 2 & 3");
        ESP_LOGW(TAG, "Set WiFi via web config UI (http://<device-ip>) then rerun");
    } else {
        ESP_LOGI(TAG, "=== TEST 2: Cellular → WiFi ===");

        /* Connect WiFi */
        ret = wifi_start();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "WiFi connect failed — skipping Tests 2 & 3");
            goto results;
        }

        /* Tear down cellular */
        ESP_LOGI(TAG, "Stopping cellular...");
        ml_cellular_data_stop();
        ml_cellular_deinit();
        vTaskDelay(pdMS_TO_TICKS(1000));

        /* Rebind to WiFi */
        test2 = do_rebind_test("TEST 2: Cell->WiFi rebind");

        /* Stabilize */
        ESP_LOGI(TAG, "Stabilizing 15s on WiFi...");
        vTaskDelay(pdMS_TO_TICKS(15000));

        /* ================================================================
         * Test 3: WiFi → Cellular rebind
         * ================================================================ */
        ESP_LOGI(TAG, "=== TEST 3: WiFi → Cellular ===");

        /* Restart cellular */
        ESP_LOGI(TAG, "Restarting cellular...");
        ret = ml_cellular_init(&cell_config);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Cellular reinit failed: %s", esp_err_to_name(ret));
            goto results;
        }
        ret = ml_cellular_connect();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Cellular reconnect failed: %s", esp_err_to_name(ret));
            goto results;
        }
        ESP_LOGI(TAG, "Cellular reconnected: %s",
                 ml_cellular_get_data_mode() == ML_DATA_MODE_PPP ? "PPP" : "AT socket");

        /* Stop WiFi */
        wifi_stop();
        vTaskDelay(pdMS_TO_TICKS(1000));

        /* Rebind to cellular */
        test3 = do_rebind_test("TEST 3: WiFi->Cell rebind");
    }

results:
    printf("\n");
    printf("================================================================\n");
    printf("  REBIND FULL TEST RESULTS\n");
    printf("================================================================\n");
    printf("  Test 1 (PPP->PPP):    %s\n", test1 ? "PASS" : "FAIL");
    printf("  Test 2 (Cell->WiFi):  %s\n", has_wifi ? (test2 ? "PASS" : "FAIL") : "SKIP");
    printf("  Test 3 (WiFi->Cell):  %s\n", has_wifi ? (test3 ? "PASS" : "FAIL") : "SKIP");
    printf("================================================================\n");
    bool all_pass = test1 && (!has_wifi || (test2 && test3));
    printf("  OVERALL: %s\n", all_pass ? "PASS" : "FAIL");
    printf("================================================================\n\n");

    /* Keep running */
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        ESP_LOGI(TAG, "Status: connected=%d peers=%d sock=%d heap=%lu",
                 microlink_is_connected(ml), microlink_get_peer_count(ml),
                 ml->disco_sock4, (unsigned long)esp_get_free_heap_size());
    }
}
