/**
 * @file main.c
 * @brief Cellular Heartbeat — Bidirectional UDP over 4G Tailscale VPN
 *
 * Demonstrates MicroLink as the transport layer for a periodic heartbeat
 * system over 4G cellular. The transport (4G cellular → Tailscale VPN →
 * encrypted UDP) is fully functional with bidirectional communication.
 * The message protocol uses a simplified binary format — replace it with
 * your application-specific serialization.
 *
 * What MicroLink provides (transport):
 *   - 4G cellular connectivity via SIM7600/SIM7670 (PPP or AT socket bridge)
 *   - Tailscale VPN with WireGuard encryption
 *   - NAT traversal (STUN + DERP relay fallback)
 *   - Bidirectional UDP send/recv on any port
 *   - WiFi/cellular failover (see failover_connect example)
 *
 * What can be implemented on top (application protocol):
 *   - Custom message serialization (CDR, protobuf, etc.)
 *   - Session management and handshake
 *   - Checksums and sequence numbers
 *   - Configurable heartbeat rate and timeout detection
 *
 * Hardware:
 *   Seeed Studio XIAO ESP32S3 + Waveshare SIM7600X 4G Module
 *   (or LILYGO T-SIM7670G-S3 — change board in sdkconfig.defaults)
 *
 * Credentials: All via menuconfig (git-ignored sdkconfig).
 *   See sdkconfig.credentials.example for template.
 *
 * Testing (verifies transport works end-to-end):
 *
 *   # From any machine on the same Tailscale network:
 *   echo "ping" | nc -u <ESP32_TAILSCALE_IP> 9000
 *
 *   # Interactive:
 *   nc -u <ESP32_TAILSCALE_IP> 9000
 *   Type: ping, stop, start, stats
 */

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#include "microlink.h"
#include "microlink_internal.h"
#include "ml_cellular.h"
#include "ml_config_httpd.h"

static const char *TAG = "cell_hb";

#define TAILSCALE_AUTH_KEY   CONFIG_ML_TAILSCALE_AUTH_KEY

/* heartbeat protocol settings */
#define HB_PORT              9000
#define HB_RATE_HZ      5       /* 5 Hz = 200ms interval */
#define HB_INTERVAL_MS      (1000 / HB_RATE_HZ)
#define HB_TIMEOUT_MS        3000    /* 3 seconds = ~15 missed heartbeats */
#define MAIN_LOOP_MS      20      /* 50 Hz main loop */
#define STATUS_INTERVAL_MS 10000  /* Print status every 10s */

/* ============================================================================
 * Heartbeat Protocol (Placeholder)
 *
 * Simplified binary message format for transport testing. Replace with your
 * application-specific serialization. The MicroLink UDP API used here
 * (microlink_udp_send/recv) stays the same regardless of what message
 * format you serialize into the payload.
 * ========================================================================== */

typedef enum {
    HB_STATE_DISCONNECTED = 0,   /* No operator station connected */
    HB_STATE_ACTIVE,             /* Operator connected, system running */
    HB_STATE_STOPPED,            /* E-stop pressed by operator */
    HB_STATE_FAULT,              /* Heartbeat timeout — operator lost */
} hb_state_t;

typedef enum {
    HB_MSG_HEARTBEAT  = 0x01,
    HB_MSG_STOP       = 0x02,
    HB_MSG_START      = 0x03,
    HB_MSG_STATUS_REQ = 0x04,
} hb_msg_type_t;

/* Compact binary message format (16 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t  version;       /* Protocol version (0x01) */
    uint8_t  type;          /* hb_msg_type_t */
    uint8_t  state;         /* hb_state_t (sender's state) */
    uint8_t  reserved;
    uint32_t counter;       /* Sequence number */
    uint32_t timestamp_ms;  /* Sender's timestamp */
    uint16_t checksum;      /* CRC-16 (or 0 for stub) */
    uint16_t reserved2;
} hb_message_t;

static const char *hb_state_str(hb_state_t state) {
    switch (state) {
        case HB_STATE_DISCONNECTED: return "DISCONNECTED";
        case HB_STATE_ACTIVE:       return "ACTIVE";
        case HB_STATE_STOPPED:      return "STOPPED";
        case HB_STATE_FAULT:        return "FAULT";
        default:                       return "UNKNOWN";
    }
}

/* ============================================================================
 * Placeholder state — replace with your protocol's remote registry
 * (connected remote state tracking)
 * ========================================================================== */

static struct {
    hb_state_t state;
    uint32_t heartbeat_counter;
    uint64_t last_hb_recv_ms;
    uint64_t last_hb_send_ms;
    uint32_t operator_ip;           /* Operator station VPN IP */
    uint16_t operator_port;         /* Operator station port */
    uint32_t hb_recv_count;
    uint32_t hb_send_count;
    uint32_t hb_timeout_count;
    bool     operator_known;        /* Have we heard from operator? */
} hb_ctx = {0};

/* ============================================================================
 * Robot Control Stub — replace with actual motor/actuator shutdown
 * ========================================================================== */

static void robot_emergency_stop(void) {
    /* STUB: Set GPIO, send CAN message, disable motor drivers, etc. */
    static bool printed = false;
    if (!printed) {
        ESP_LOGW(TAG, "*** EMERGENCY STOP ACTIVATED ***");
        ESP_LOGW(TAG, "    (stub — replace with actual motor shutdown)");
        printed = true;
    }
}

static void robot_allow_operation(void) {
    /* STUB: Re-enable motor drivers, clear fault, etc. */
}

/* ============================================================================
 * Placeholder heartbeat functions — replace with your actual protocol
 *
 * These demonstrate the integration pattern:
 *   - hb_on_recv() is called with raw UDP payload bytes
 *   - hb_update() is called every loop iteration
 *   - microlink_udp_send/recv handle the transport
 *
 * Your implementation would deserialize your application messages from the
 * UDP payload, validate checksums, and manage state.
 * ========================================================================== */
static void hb_init(void) {
    memset(&hb_ctx, 0, sizeof(hb_ctx));
    hb_ctx.state = HB_STATE_DISCONNECTED;
    ESP_LOGI(TAG, "Heartbeat initialized (state: DISCONNECTED)");
    ESP_LOGI(TAG, "  Heartbeat: %d Hz (%d ms interval)", HB_RATE_HZ, HB_INTERVAL_MS);
    ESP_LOGI(TAG, "  Timeout:   %d ms (%d missed heartbeats)",
             HB_TIMEOUT_MS, HB_TIMEOUT_MS / HB_INTERVAL_MS);
}

/**
 * Process a received UDP message.
 * Called whenever data arrives from the network.
 */
static void hb_on_recv(uint32_t src_ip, uint16_t src_port,
                                   const uint8_t *data, size_t len,
                                   uint64_t now_ms) {
    /* Remember operator station */
    if (!hb_ctx.operator_known || hb_ctx.operator_ip != src_ip) {
        char ip_str[16];
        microlink_ip_to_str(src_ip, ip_str);
        ESP_LOGI(TAG, "Operator station: %s:%u", ip_str, src_port);
    }
    hb_ctx.operator_ip = src_ip;
    hb_ctx.operator_port = src_port;
    hb_ctx.operator_known = true;

    /* Try binary message format first */
    if (len == sizeof(hb_message_t)) {
        const hb_message_t *msg = (const hb_message_t *)data;
        if (msg->version == 0x01) {
            hb_ctx.last_hb_recv_ms = now_ms;
            hb_ctx.hb_recv_count++;

            switch (msg->type) {
                case HB_MSG_HEARTBEAT:
                    if (hb_ctx.state == HB_STATE_DISCONNECTED ||
                        hb_ctx.state == HB_STATE_FAULT) {
                        hb_ctx.state = HB_STATE_ACTIVE;
                        ESP_LOGI(TAG, "HB: → ACTIVE (operator connected)");
                        robot_allow_operation();
                    }
                    break;
                case HB_MSG_STOP:
                    hb_ctx.state = HB_STATE_STOPPED;
                    ESP_LOGW(TAG, "HB: → STOPPED (E-stop pressed by operator)");
                    robot_emergency_stop();
                    break;
                case HB_MSG_START:
                    hb_ctx.state = HB_STATE_ACTIVE;
                    ESP_LOGI(TAG, "HB: → ACTIVE (E-stop released)");
                    robot_allow_operation();
                    break;
                default:
                    break;
            }
            return;
        }
    }

    /* Fallback: text commands for interactive testing */
    char msg_str[128];
    size_t copy_len = len < sizeof(msg_str) - 1 ? len : sizeof(msg_str) - 1;
    memcpy(msg_str, data, copy_len);
    msg_str[copy_len] = '\0';
    /* Strip trailing newline */
    while (copy_len > 0 && (msg_str[copy_len-1] == '\n' || msg_str[copy_len-1] == '\r')) {
        msg_str[--copy_len] = '\0';
    }

    hb_ctx.last_hb_recv_ms = now_ms;  /* Any valid message resets timeout */
    hb_ctx.hb_recv_count++;

    if (strcmp(msg_str, "ping") == 0) {
        if (hb_ctx.state == HB_STATE_DISCONNECTED ||
            hb_ctx.state == HB_STATE_FAULT) {
            hb_ctx.state = HB_STATE_ACTIVE;
            ESP_LOGI(TAG, "HB: → ACTIVE (operator connected)");
            robot_allow_operation();
        }
    } else if (strcmp(msg_str, "stop") == 0) {
        hb_ctx.state = HB_STATE_STOPPED;
        ESP_LOGW(TAG, "HB: → STOPPED (text command)");
        robot_emergency_stop();
    } else if (strcmp(msg_str, "start") == 0) {
        hb_ctx.state = HB_STATE_ACTIVE;
        ESP_LOGI(TAG, "HB: → ACTIVE (text command)");
        robot_allow_operation();
    }

    char ip_str[16];
    microlink_ip_to_str(src_ip, ip_str);
    ESP_LOGI(TAG, "[RECV] ← %s:%u \"%s\" (%u bytes)", ip_str, src_port, msg_str, (unsigned)len);
}

/**
 * Periodic update — sends heartbeats and checks timeouts.
 * Called every main loop iteration (~20ms).
 */
static void hb_update(microlink_udp_socket_t *sock, uint64_t now_ms) {
    /* --- Check heartbeat timeout --- */
    if (hb_ctx.state == HB_STATE_ACTIVE && hb_ctx.operator_known) {
        if (now_ms - hb_ctx.last_hb_recv_ms > HB_TIMEOUT_MS) {
            hb_ctx.state = HB_STATE_FAULT;
            hb_ctx.hb_timeout_count++;
            ESP_LOGW(TAG, "HB: → FAULT (heartbeat timeout: %lu ms since last)",
                     (unsigned long)(now_ms - hb_ctx.last_hb_recv_ms));
            robot_emergency_stop();
        }
    }

    /* --- Send heartbeat at configured rate --- */
    if (!hb_ctx.operator_known) return;
    if (now_ms - hb_ctx.last_hb_send_ms < HB_INTERVAL_MS) return;

    hb_message_t hb = {
        .version = 0x01,
        .type = HB_MSG_HEARTBEAT,
        .state = (uint8_t)hb_ctx.state,
        .counter = hb_ctx.heartbeat_counter++,
        .timestamp_ms = (uint32_t)now_ms,
        .checksum = 0,  /* Stub — add CRC-16 in production */
    };

    esp_err_t err = microlink_udp_send(sock, hb_ctx.operator_ip, HB_PORT,
                                        &hb, sizeof(hb));
    if (err == ESP_OK) {
        hb_ctx.hb_send_count++;
        hb_ctx.last_hb_send_ms = now_ms;
    }
}

/**
 * Get current heartbeat state.
 * Call from robot control system to determine if safe to operate.
 */
static hb_state_t hb_get_state(void) {
    return hb_ctx.state;
}

/* ============================================================================
 * Main Application
 * ========================================================================== */

void app_main(void) {
    /* Initialize NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Initialize esp_netif and event loop */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    printf("\n");
    printf("================================================================\n");
    printf("  Cellular Heartbeat — Bidirectional UDP over 4G Tailscale VPN\n");
    printf("  Board: XIAO ESP32S3 + Waveshare SIM7600X\n");
    printf("  Protocol: %d Hz heartbeat, %d ms timeout\n",
           HB_RATE_HZ, HB_TIMEOUT_MS);
    printf("================================================================\n\n");

    ESP_LOGI(TAG, "Free heap: %lu bytes (PSRAM: %lu bytes)",
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    /* ================================================================
     * Step 1: Initialize SIM7600 cellular modem
     * ================================================================ */

    ESP_LOGI(TAG, "=== Step 1: Initializing SIM7600 modem ===");

    ml_cellular_config_t cell_config = ML_CELLULAR_DEFAULT_CONFIG();
    cell_config.tx_pin = CONFIG_ML_CELLULAR_TX_PIN;
    cell_config.rx_pin = CONFIG_ML_CELLULAR_RX_PIN;

    const char *sim_pin = CONFIG_ML_CELLULAR_SIM_PIN;
    if (sim_pin && sim_pin[0]) {
        cell_config.sim_pin = sim_pin;
    }
    const char *apn = CONFIG_ML_CELLULAR_APN;
    if (apn && apn[0]) {
        cell_config.apn = apn;
    }
    const char *ppp_user = CONFIG_ML_CELLULAR_PPP_USER;
    if (ppp_user && ppp_user[0]) {
        cell_config.ppp_user = ppp_user;
    }
    const char *ppp_pass = CONFIG_ML_CELLULAR_PPP_PASS;
    if (ppp_pass && ppp_pass[0]) {
        cell_config.ppp_pass = ppp_pass;
    }

    /* NVS overrides (web UI settings take precedence over Kconfig) */
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
        ESP_LOGE(TAG, "Cellular init failed: %s", esp_err_to_name(ret));
        ESP_LOGE(TAG, "Check: wiring, SIM card, antenna, power supply");
        return;
    }

    ml_cellular_info_t cell_info;
    ml_cellular_get_info(&cell_info);
    ESP_LOGI(TAG, "Model: %s  IMEI: %s", cell_info.model, cell_info.imei);
    ESP_LOGI(TAG, "ICCID: %s", cell_info.iccid);
    ESP_LOGI(TAG, "Operator: %s  Signal: %d (%d dBm)",
             cell_info.operator_name, cell_info.rssi, cell_info.rssi_dbm);

    /* ================================================================
     * Step 2: Connect cellular data (PPP primary, AT socket fallback)
     * ================================================================ */

    ESP_LOGI(TAG, "=== Step 2: Connecting cellular data ===");

    ret = ml_cellular_connect();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Cellular data connection failed: %s", esp_err_to_name(ret));
        return;
    }

    ml_cellular_data_mode_t data_mode = ml_cellular_get_data_mode();
    ESP_LOGI(TAG, "Cellular data active via %s",
             data_mode == ML_DATA_MODE_PPP ? "PPP (lwIP sockets)"
                                           : "AT socket bridge");

    /* ================================================================
     * Step 3: Initialize MicroLink (Tailscale)
     * ================================================================ */

    ESP_LOGI(TAG, "=== Step 3: Starting MicroLink (Tailscale) over 4G ===");

    const char *device_name = microlink_imei_device_name();
    if (!device_name || device_name[0] == '\0') {
        const char *kconfig_name = CONFIG_ML_DEVICE_NAME;
        if (kconfig_name && kconfig_name[0]) {
            device_name = kconfig_name;
        } else {
            device_name = microlink_default_device_name();
        }
    }
    ESP_LOGI(TAG, "Device name: %s", device_name);

    microlink_config_t config = {
        .auth_key = TAILSCALE_AUTH_KEY,
        .device_name = device_name,
        .enable_derp = true,
        .enable_stun = true,
        .enable_disco = true,
        .max_peers = CONFIG_ML_MAX_PEERS,
    };

    microlink_t *ml = microlink_init(&config);
    if (!ml) {
        ESP_LOGE(TAG, "Failed to initialize MicroLink");
        return;
    }

    ESP_ERROR_CHECK(microlink_start(ml));

    ESP_LOGI(TAG, "Waiting for Tailscale connection...");
    while (!microlink_is_connected(ml)) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    uint32_t vpn_ip = microlink_get_vpn_ip(ml);
    char ip_buf[16];
    microlink_ip_to_str(vpn_ip, ip_buf);

    printf("\n");
    printf("================================================================\n");
    printf("  CONNECTED via 4G Cellular!\n");
    printf("  VPN IP:  %s\n", ip_buf);
    printf("  Device:  %s\n", device_name);
    printf("  Signal:  %d dBm\n", cell_info.rssi_dbm);
    printf("================================================================\n\n");

    /* ================================================================
     * Step 4: Create UDP socket for heartbeat protocol
     * ================================================================ */

    microlink_udp_socket_t *sock = microlink_udp_create(ml, HB_PORT);
    if (!sock) {
        ESP_LOGE(TAG, "Failed to create UDP socket on port %d", HB_PORT);
        return;
    }
    ESP_LOGI(TAG, "UDP socket listening on port %d", HB_PORT);

    /* ================================================================
     * Step 5: Initialize heartbeat
     * ================================================================ */

    hb_init();

    /* Pre-configure operator IP if set via Kconfig */
    const char *op_ip_str = CONFIG_ML_EXAMPLE_OPERATOR_PEER_IP;
    if (op_ip_str && op_ip_str[0] != '\0') {
        hb_ctx.operator_ip = microlink_parse_ip(op_ip_str);
        if (hb_ctx.operator_ip != 0) {
            hb_ctx.operator_known = true;
            hb_ctx.operator_port = HB_PORT;
            ESP_LOGI(TAG, "Operator station pre-configured: %s:%d", op_ip_str, HB_PORT);
        }
    }

    printf("\n");
    printf("============================================\n");
    printf("  READY — Waiting for operator\n");
    printf("============================================\n");
    printf("\n");
    printf("Test from your PC (same Tailscale network):\n");
    printf("  echo 'ping' | nc -u %s %d\n", ip_buf, HB_PORT);
    printf("  # Commands: ping, stop, start, echo:text, stats\n");
    printf("\n");

    /* ================================================================
     * Main Loop — 50 Hz
     *
     * 1. Receive incoming UDP messages
     * 2. Call heartbeat update (heartbeats, timeouts)
     * 3. Check safety state
     * 4. Keep VPN alive
     * ================================================================ */

    uint64_t last_status_ms = 0;

    while (1) {
        uint64_t now_ms = (uint64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);

        /* --- Receive UDP messages --- */
        uint8_t recv_buf[256];
        size_t recv_len = sizeof(recv_buf);
        uint32_t src_ip;
        uint16_t src_port;

        esp_err_t err = microlink_udp_recv(sock, &src_ip, &src_port,
                                            recv_buf, &recv_len, 0);
        if (err == ESP_OK && recv_len > 0) {
            hb_on_recv(src_ip, src_port, recv_buf, recv_len, now_ms);

            /* Handle text response commands */
            char msg_str[128];
            size_t copy_len = recv_len < sizeof(msg_str) - 1 ? recv_len : sizeof(msg_str) - 1;
            memcpy(msg_str, recv_buf, copy_len);
            msg_str[copy_len] = '\0';
            while (copy_len > 0 && (msg_str[copy_len-1] == '\n' || msg_str[copy_len-1] == '\r')) {
                msg_str[--copy_len] = '\0';
            }

            char response[256];
            bool send_response = false;

            if (strcmp(msg_str, "ping") == 0) {
                snprintf(response, sizeof(response), "pong (state: %s, signal: %d dBm)",
                         hb_state_str(hb_ctx.state), cell_info.rssi_dbm);
                send_response = true;
            } else if (strncmp(msg_str, "echo:", 5) == 0) {
                snprintf(response, sizeof(response), "ECHO(4G): %s", msg_str + 5);
                send_response = true;
            } else if (strcmp(msg_str, "stats") == 0) {
                ml_cellular_get_info(&cell_info);
                snprintf(response, sizeof(response),
                         "state=%s hb_rx=%lu hb_tx=%lu timeouts=%lu signal=%ddBm heap=%lu",
                         hb_state_str(hb_ctx.state),
                         (unsigned long)hb_ctx.hb_recv_count,
                         (unsigned long)hb_ctx.hb_send_count,
                         (unsigned long)hb_ctx.hb_timeout_count,
                         cell_info.rssi_dbm,
                         (unsigned long)esp_get_free_heap_size());
                send_response = true;
            }

            if (send_response) {
                microlink_udp_send(sock, src_ip, src_port, response, strlen(response));
            }
        }

        /* --- heartbeat periodic update --- */
        hb_update(sock, now_ms);

        /* --- Check safety state for robot control --- */
        hb_state_t state = hb_get_state();
        if (state == HB_STATE_STOPPED || state == HB_STATE_FAULT) {
            robot_emergency_stop();
        }

        /* --- Periodic status --- */
        if (now_ms - last_status_ms >= STATUS_INTERVAL_MS) {
            last_status_ms = now_ms;

            ml_cellular_get_info(&cell_info);
            int peer_count = microlink_is_connected(ml) ? microlink_get_peer_count(ml) : 0;

            ESP_LOGI(TAG, "[STATUS] state=%s | signal=%ddBm | peers=%d | "
                     "hb_rx=%lu hb_tx=%lu timeout=%lu | heap=%lu",
                     hb_state_str(hb_ctx.state),
                     cell_info.rssi_dbm,
                     peer_count,
                     (unsigned long)hb_ctx.hb_recv_count,
                     (unsigned long)hb_ctx.hb_send_count,
                     (unsigned long)hb_ctx.hb_timeout_count,
                     (unsigned long)esp_get_free_heap_size());
        }

        /* --- Loop delay (50 Hz) --- */
        vTaskDelay(pdMS_TO_TICKS(MAIN_LOOP_MS));
    }
}
