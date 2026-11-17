/**
 * @file ml_cellular.c
 * @brief MicroLink Cellular Module — SIM7600 4G Modem Driver + PPP
 *
 * Two-phase operation:
 *   1. AT command mode: Initialize modem, check SIM, register on network, get IMEI
 *   2. PPP data mode: Dial ATD*99#, feed UART data to esp_netif PPP interface
 *
 * The PPP interface creates a standard lwIP netif, so all existing MicroLink
 * socket operations (STUN, DERP TLS, DISCO UDP) work unchanged over cellular.
 *
 * Hardware: Seeed Studio XIAO ESP32S3 + Waveshare SIM7600X 4G Module
 */

#include "ml_cellular.h"
#include "ml_at_validate.h"
#include "microlink_internal.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_netif_ppp.h"
#include "lwip/ip6_addr.h"
#include "esp_event.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef CONFIG_ML_ENABLE_CELLULAR

static const char *TAG = "ml_cell";

/* ============================================================================
 * Internal State
 * ========================================================================== */

#define UART_NUM            UART_NUM_1
#define UART_RX_BUF_SIZE    (16 * 1024)  /* 16KB — SIM7600 needs large buffers for PPP */
#define UART_TX_BUF_SIZE    (4 * 1024)   /* 4KB TX buffer */
#define AT_TIMEOUT_MS       5000
#define AT_SHORT_TIMEOUT_MS 2000
#define PPP_CONNECT_TIMEOUT_MS 30000

/* PPP event bits */
#define PPP_GOT_IP_BIT      BIT0
#define PPP_LOST_IP_BIT     BIT1
#define PPP_CONNECT_FAIL    BIT2
#define PPP_CHAP_FAIL_BIT   BIT3
#define PPP_CLOSED_BIT      BIT4   /* ppp_close() completed (PPPERR_USER callback fired) */
#define PPP_GOT_IP6_BIT     BIT5

static struct {
    ml_cellular_config_t config;   /* string fields point at the copies below */
    char apn[ML_AT_APN_MAX + 1];
    char sim_pin[ML_AT_PIN_MAX + 1];
    char ppp_user[ML_AT_CRED_MAX + 1];
    char ppp_pass[ML_AT_CRED_MAX + 1];
    volatile ml_cellular_state_t state;
    ml_cellular_info_t info;
    bool uart_installed;
    ml_cellular_data_mode_t data_mode;

    /* PPP */
    esp_netif_t *ppp_netif;
    TaskHandle_t ppp_task;
    EventGroupHandle_t ppp_events;
    volatile bool ppp_running;
    esp_event_handler_instance_t ip_event_handler;
    esp_event_handler_instance_t ppp_status_handler;
} s_cell = {
    .state = ML_CELL_STATE_OFF,
    .data_mode = ML_DATA_MODE_NONE,
};

/* Serialises every AT command exchange on the modem UART: this driver's
 * commands, the AT socket bridge (ml_at_socket.c) and application
 * pass-through commands. Created on first init and never deleted, so a task
 * blocked on it can never be left waiting on a freed semaphore. */
static SemaphoreHandle_t s_uart_lock;

bool ml_cellular_uart_lock(void)
{
    if (!s_uart_lock) return false;
    return xSemaphoreTake(s_uart_lock, portMAX_DELAY) == pdTRUE;
}

void ml_cellular_uart_unlock(void)
{
    if (s_uart_lock) xSemaphoreGive(s_uart_lock);
}

/* ============================================================================
 * AT Command Helpers (same proven pattern from sim7600_4g_test)
 * ========================================================================== */

/* Send one AT command and collect the response. Caller holds s_uart_lock.
 * Command arguments are never logged in clear: SIM PIN and PPP password
 * commands are redacted (ml_at_redact_cmd). */
static int at_send_cmd_locked(const char *cmd, char *response, size_t resp_size, int timeout_ms)
{
    if (!response || resp_size < 2) return -1;
    memset(response, 0, resp_size);

    char log_cmd[48];
    char cmd_buf[256];
    size_t cmd_len = strlen(cmd);
    if (cmd_len > sizeof(cmd_buf) - 3) {
        /* Truncating would drop the CR and glue the next command onto it */
        ESP_LOGE(TAG, "AT command too long (%u bytes): %s", (unsigned)cmd_len,
                 ml_at_redact_cmd(cmd, log_cmd, sizeof(log_cmd)));
        return -1;
    }

    uart_flush_input(UART_NUM);

    memcpy(cmd_buf, cmd, cmd_len);
    cmd_buf[cmd_len] = '\r';
    cmd_buf[cmd_len + 1] = '\n';
    uart_write_bytes(UART_NUM, cmd_buf, cmd_len + 2);
    ml_at_secure_zero(cmd_buf, sizeof(cmd_buf));

    ESP_LOGD(TAG, ">> %s", ml_at_redact_cmd(cmd, log_cmd, sizeof(log_cmd)));

    int total_read = 0;
    int64_t start = esp_timer_get_time();
    int64_t timeout_us = (int64_t)timeout_ms * 1000;

    while ((esp_timer_get_time() - start) < timeout_us) {
        if ((size_t)total_read >= resp_size - 1) {
            /* Buffer full without a final result code: stop instead of
             * spinning on zero-length reads until the timeout. The rest is
             * discarded by the next command's flush. */
            ESP_LOGW(TAG, "AT response truncated at %d bytes", total_read);
            break;
        }
        int len = uart_read_bytes(UART_NUM,
                                   (uint8_t *)(response + total_read),
                                   resp_size - total_read - 1,
                                   pdMS_TO_TICKS(100));
        if (len > 0) {
            total_read += len;
            response[total_read] = '\0';

            if (strstr(response, "OK") ||
                strstr(response, "ERROR") ||
                strstr(response, "+CME ERROR") ||
                strstr(response, "+CMS ERROR") ||
                strstr(response, "CONNECT")) {
                break;
            }
        }
    }

    if (total_read > 0) {
        char *display = response;
        while (*display == '\r' || *display == '\n') display++;
        ESP_LOGD(TAG, "<< %s", display);
    } else {
        ESP_LOGW(TAG, "<< (no response to '%s')",
                 ml_at_redact_cmd(cmd, log_cmd, sizeof(log_cmd)));
        return -1;
    }

    return total_read;
}

static int at_send_cmd(const char *cmd, char *response, size_t resp_size, int timeout_ms)
{
    if (!ml_cellular_uart_lock()) return -1;
    int ret = at_send_cmd_locked(cmd, response, resp_size, timeout_ms);
    ml_cellular_uart_unlock();
    return ret;
}

static bool at_cmd_ok_locked(const char *cmd, int timeout_ms)
{
    char resp[512];
    int len = at_send_cmd_locked(cmd, resp, sizeof(resp), timeout_ms);
    return (len > 0 && strstr(resp, "OK") != NULL);
}

static bool at_cmd_ok(const char *cmd, int timeout_ms)
{
    char resp[512];
    int len = at_send_cmd(cmd, resp, sizeof(resp), timeout_ms);
    return (len > 0 && strstr(resp, "OK") != NULL);
}

/* Extract a value after a prefix from AT response (e.g. "+CGSN: 12345...") */
static bool at_extract_value(const char *resp, const char *prefix, char *out, size_t out_size)
{
    const char *p = NULL;
    if (prefix && prefix[0]) {
        p = strstr(resp, prefix);
    }
    if (!p) {
        /* No prefix or not found — extract first non-empty line (e.g. AT+CGSN returns bare IMEI) */
        p = resp;
        while (*p == '\r' || *p == '\n' || *p == ' ') p++;
    } else {
        p += strlen(prefix);
        while (*p == ' ' || *p == ':') p++;
    }
    const char *end = p;
    while (*end && *end != '\r' && *end != '\n') end++;
    size_t len = (size_t)(end - p);
    if (len == 0 || len >= out_size) return false;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

/* ============================================================================
 * UART Initialization
 * ========================================================================== */

static esp_err_t uart_init(void)
{
    uart_config_t uart_config = {
        .baud_rate = s_cell.config.baud_rate,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t err;

    err = uart_driver_install(UART_NUM, UART_RX_BUF_SIZE, UART_TX_BUF_SIZE, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART driver install failed: %s", esp_err_to_name(err));
        return err;
    }

    err = uart_param_config(UART_NUM, &uart_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART param config failed: %s", esp_err_to_name(err));
        uart_driver_delete(UART_NUM);
        return err;
    }

    err = uart_set_pin(UART_NUM, s_cell.config.tx_pin, s_cell.config.rx_pin,
                        UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART set pin failed: %s", esp_err_to_name(err));
        uart_driver_delete(UART_NUM);
        return err;
    }

    /* Set RX timeout to trigger events faster for PPP */
    uart_set_rx_timeout(UART_NUM, 1);

    s_cell.uart_installed = true;
    ESP_LOGI(TAG, "UART%d: TX=GPIO%d, RX=GPIO%d, Baud=%d",
             UART_NUM, s_cell.config.tx_pin, s_cell.config.rx_pin, s_cell.config.baud_rate);

    return ESP_OK;
}

/* ============================================================================
 * Modem Setup (AT command phase)
 * ========================================================================== */

/* "+++" escape (back to command mode if the modem was left in data mode).
 * SIM7600/SIM7670 need 1 s of silence before and after it, so no other
 * bytes may be sent meanwhile: caller holds s_uart_lock. */
static void escape_data_mode_locked(void)
{
    vTaskDelay(pdMS_TO_TICKS(1100));
    uart_write_bytes(UART_NUM, "+++", 3);
    vTaskDelay(pdMS_TO_TICKS(1100));
    uart_flush_input(UART_NUM);
}

/* Probe the other common baud rates, in case the modem was left at another
 * speed with AT+IPR. On success the UART and s_cell.config.baud_rate match
 * the modem. Caller holds s_uart_lock: the UART rate changes underneath any
 * other command, so nothing else may run in between. */
static bool probe_alt_bauds_locked(void)
{
#ifdef CONFIG_ML_BOARD_LILYGO_T_SIM7670G
    /* SIM7670G: only probe 115200 — unreliable at higher rates */
    int try_bauds[] = {115200};
    int num_bauds = 1;
#else
    int try_bauds[] = {921600, 460800, 115200};
    int num_bauds = 3;
#endif
    for (int b = 0; b < num_bauds; b++) {
        if (try_bauds[b] == s_cell.config.baud_rate) continue;
        ESP_LOGI(TAG, "Trying alternate baud rate %d...", try_bauds[b]);
        uart_set_baudrate(UART_NUM, try_bauds[b]);
        vTaskDelay(pdMS_TO_TICKS(100));
        /* Also try +++ at this baud in case modem is stuck in data mode */
        escape_data_mode_locked();
        if (at_cmd_ok_locked("AT", AT_SHORT_TIMEOUT_MS)) {
            ESP_LOGI(TAG, "Modem responding at %d baud", try_bauds[b]);
            /* AT+IPR persists in the modem, so a modem left at another
             * speed (e.g. by an earlier fast-baud attempt) stays there
             * forever. Bring it back to the configured rate. */
            int want = s_cell.config.baud_rate;
            char ipr[32];
            snprintf(ipr, sizeof(ipr), "AT+IPR=%d", want);
            if (at_cmd_ok_locked(ipr, AT_SHORT_TIMEOUT_MS)) {
                /* The modem acknowledged: it should be at `want` now.
                 * Give the UART time to settle and retry the check a
                 * few times. */
                vTaskDelay(pdMS_TO_TICKS(300));
                uart_set_baudrate(UART_NUM, want);
                bool restored = false;
                for (int v = 0; v < 4 && !restored; v++) {
                    vTaskDelay(pdMS_TO_TICKS(300));
                    uart_flush_input(UART_NUM);
                    restored = at_cmd_ok_locked("AT", AT_SHORT_TIMEOUT_MS);
                }
                if (restored) {
                    ESP_LOGI(TAG, "Modem baud restored to %d", want);
                    return true;
                }
                /* The switch did not take (or the reply was lost):
                 * go back to the rate that worked a moment ago. */
                ESP_LOGW(TAG, "No answer at %d after AT+IPR; trying %d again",
                         want, try_bauds[b]);
                uart_set_baudrate(UART_NUM, try_bauds[b]);
                vTaskDelay(pdMS_TO_TICKS(300));
                uart_flush_input(UART_NUM);
                if (at_cmd_ok_locked("AT", AT_SHORT_TIMEOUT_MS)) {
                    ESP_LOGW(TAG, "Modem stays at %d baud", try_bauds[b]);
                    s_cell.config.baud_rate = try_bauds[b];
                    return true;
                }
                continue;   /* lost at both rates: keep probing */
            }
            s_cell.config.baud_rate = try_bauds[b];
            return true;
        }
    }
    /* Restore original baud rate and keep trying */
    uart_set_baudrate(UART_NUM, s_cell.config.baud_rate);
    return false;
}

/* A modem left in a data call by an earlier session (for example the ESP32
 * reset in the middle of PPP) answers AT after +++, but the call stays up and
 * buffered PPP frames can still arrive on the UART, garbling the next replies.
 * Hang the call up and drain the UART. ATH is harmless when no call is up. */
static void hangup_stale_call(void)
{
    at_cmd_ok("ATH", AT_SHORT_TIMEOUT_MS);
    vTaskDelay(pdMS_TO_TICKS(300));
    if (ml_cellular_uart_lock()) {
        uart_flush_input(UART_NUM);
        ml_cellular_uart_unlock();
    }
}

static esp_err_t modem_wait_ready(void)
{
    ESP_LOGI(TAG, "Waiting for modem...");

    /* If modem is stuck in data mode (e.g. from a previous PPP session that
     * didn't cleanly exit), send +++ escape sequence to return to command mode. */
    if (!ml_cellular_uart_lock()) return ESP_ERR_INVALID_STATE;
    escape_data_mode_locked();
    ml_cellular_uart_unlock();

    /* Try AT command with retries (modem may still be booting) */
    for (int i = 0; i < 10; i++) {
        if (at_cmd_ok("AT", AT_SHORT_TIMEOUT_MS)) {
            s_cell.state = ML_CELL_STATE_AT_OK;
            ESP_LOGI(TAG, "Modem responding at %d baud", s_cell.config.baud_rate);
            hangup_stale_call();
            return ESP_OK;
        }
        /* After 3 failed attempts, try common baud rates in case the modem
         * was previously set to a different speed with AT+IPR */
        if (i == 3) {
            if (!ml_cellular_uart_lock()) return ESP_ERR_INVALID_STATE;
            bool found = probe_alt_bauds_locked();
            ml_cellular_uart_unlock();
            if (found) {
                s_cell.state = ML_CELL_STATE_AT_OK;
                hangup_stale_call();
                return ESP_OK;
            }
        }
        ESP_LOGW(TAG, "AT retry %d/10...", i + 1);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    ESP_LOGE(TAG, "Modem not responding after 10 retries");
    s_cell.state = ML_CELL_STATE_ERROR;
    return ESP_ERR_TIMEOUT;
}

static esp_err_t modem_setup(void)
{
    char resp[512];

    /* Disable echo */
    at_cmd_ok("ATE0", AT_SHORT_TIMEOUT_MS);

    /* Get module model */
    at_send_cmd("AT+CGMM", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
    at_extract_value(resp, NULL, s_cell.info.model, sizeof(s_cell.info.model));
    ESP_LOGI(TAG, "Model: %s", s_cell.info.model);

    /* Get firmware version */
    at_send_cmd("AT+CGMR", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
    at_extract_value(resp, NULL, s_cell.info.firmware, sizeof(s_cell.info.firmware));

    /* Get IMEI */
    at_send_cmd("AT+CGSN", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
    at_extract_value(resp, NULL, s_cell.info.imei, sizeof(s_cell.info.imei));
    /* Validate IMEI is numeric and 14-15 digits */
    bool valid_imei = (strlen(s_cell.info.imei) >= 14);
    for (size_t i = 0; i < strlen(s_cell.info.imei) && valid_imei; i++) {
        if (s_cell.info.imei[i] < '0' || s_cell.info.imei[i] > '9') valid_imei = false;
    }
    /* Identifiers: last 4 digits at INFO (logs end up in bug reports),
     * the full value only at DEBUG */
    char masked[ML_AT_MASKED_ID_SIZE];
    if (valid_imei) {
        ESP_LOGI(TAG, "IMEI: %s", ml_at_mask_id(s_cell.info.imei, masked, sizeof(masked)));
        ESP_LOGD(TAG, "IMEI (full): %s", s_cell.info.imei);
    } else {
        ESP_LOGW(TAG, "IMEI invalid (%u chars)", (unsigned)strlen(s_cell.info.imei));
        s_cell.info.imei[0] = '\0';
    }

    return ESP_OK;
}

/* SIM PIN guard. A wrong PIN must never be retried automatically: three
 * rejections PUK-lock the SIM, and net_switch / boot loops call
 * ml_cellular_init() again and again. Kept across deinit/init (RAM only),
 * so it lasts until reboot or ml_cellular_reset_sim_pin_guard(). */
static struct {
    bool blocked;       /* a PIN was rejected or attempts are nearly used up */
    bool sent_blind;    /* PIN sent once without a known attempt counter */
    bool known_good;    /* the configured PIN was accepted this boot */
} s_pin_guard;

bool ml_cellular_sim_pin_blocked(void)
{
    return s_pin_guard.blocked;
}

void ml_cellular_reset_sim_pin_guard(void)
{
    memset(&s_pin_guard, 0, sizeof(s_pin_guard));
}

/* "+CPIN: <code>" with <code> exactly @p code (so "SIM PIN" does not also
 * match "SIM PIN2" or "PH-SIM PIN") */
static bool cpin_is(const char *resp, const char *code)
{
    const char *p = strstr(resp, "+CPIN:");
    if (!p) return false;
    p += 6;
    while (*p == ' ') p++;
    size_t n = strlen(code);
    return strncmp(p, code, n) == 0 && (p[n] == '\r' || p[n] == '\n' || p[n] == '\0');
}

/* Remaining SIM PIN1 attempts via AT+SPIC ("+SPIC: <pin1>,<puk1>,<pin2>,
 * <puk2>", SIM7500/SIM7600 and A76xx/SIM767x manuals), or -1 if unknown. */
static int sim_pin_attempts_left(void)
{
    char resp[128];
    if (at_send_cmd("AT+SPIC", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS) <= 0) return -1;
    const char *p = strstr(resp, "+SPIC:");
    int pin1, puk1;
    if (!p || sscanf(p, "+SPIC: %d,%d", &pin1, &puk1) != 2 || pin1 < 0 || pin1 > 10) return -1;
    return pin1;
}

static esp_err_t sim_enter_pin(void)
{
    if (!s_cell.config.sim_pin || !s_cell.config.sim_pin[0]) {
        ESP_LOGE(TAG, "SIM requires PIN but none configured");
        return ESP_ERR_INVALID_STATE;
    }
    if (!ml_at_valid_pin(s_cell.config.sim_pin)) {
        /* Never interpolate an unchecked value into an AT command */
        ESP_LOGE(TAG, "SIM PIN is not 4-8 digits; not sending it");
        return ESP_ERR_INVALID_ARG;
    }
    if (s_pin_guard.blocked) {
        ESP_LOGE(TAG, "SIM PIN not sent: it was rejected (or too few attempts were left) "
                 "earlier; fix the PIN and reboot");
        return ESP_ERR_NOT_ALLOWED;
    }

    int left = sim_pin_attempts_left();
    if (left >= 0) {
        ESP_LOGI(TAG, "SIM PIN attempts left: %d", left);
        if (left < 2) {
            /* One wrong PIN now would need the PUK */
            ESP_LOGE(TAG, "SIM PIN not sent: only %d attempt(s) left. Unlock the SIM "
                     "in a phone, or check the PIN and reboot", left);
            s_pin_guard.blocked = true;
            return ESP_ERR_NOT_ALLOWED;
        }
    } else if (s_pin_guard.sent_blind && !s_pin_guard.known_good) {
        /* No attempt counter: send at most once per boot */
        ESP_LOGE(TAG, "SIM PIN not sent again: the modem does not report the attempts "
                 "left and the PIN was already tried this boot");
        s_pin_guard.blocked = true;
        return ESP_ERR_NOT_ALLOWED;
    } else {
        s_pin_guard.sent_blind = true;
    }

    char pin_cmd[32];
    snprintf(pin_cmd, sizeof(pin_cmd), "AT+CPIN=\"%s\"", s_cell.config.sim_pin);
    bool pin_ok = at_cmd_ok(pin_cmd, AT_TIMEOUT_MS);
    ml_at_secure_zero(pin_cmd, sizeof(pin_cmd));
    if (!pin_ok) {
        /* Rejected, or no answer (outcome unknown): never retry by itself */
        s_pin_guard.blocked = true;
        ESP_LOGE(TAG, "SIM PIN rejected; it will not be sent again until reboot");
        return ESP_ERR_INVALID_ARG;
    }
    s_pin_guard.known_good = true;
    ESP_LOGI(TAG, "SIM PIN accepted");
    return ESP_OK;
}

static esp_err_t sim_setup(void)
{
    char resp[512];

    /* Check SIM status. Ask again while the reply has no +CPIN: line: right
     * after a modem boot the SIM can still be busy, and stray bytes from an
     * earlier data call can take the place of the answer. */
    for (int i = 0; i < 5; i++) {
        at_send_cmd("AT+CPIN?", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
        if (strstr(resp, "+CPIN:")) break;
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (ml_cellular_uart_lock()) {
            uart_flush_input(UART_NUM);
            ml_cellular_uart_unlock();
        }
    }

    if (cpin_is(resp, "READY")) {
        s_cell.info.sim_ready = true;
        s_cell.state = ML_CELL_STATE_SIM_READY;
        ESP_LOGI(TAG, "SIM ready");
    } else if (cpin_is(resp, "SIM PIN")) {
        esp_err_t err = sim_enter_pin();
        if (err != ESP_OK) {
            s_cell.state = ML_CELL_STATE_ERROR;
            return err;
        }
        vTaskDelay(pdMS_TO_TICKS(2000)); /* Wait for SIM to initialize */

        /* Verify SIM is now ready */
        at_send_cmd("AT+CPIN?", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
        if (cpin_is(resp, "READY")) {
            s_cell.info.sim_ready = true;
            s_cell.state = ML_CELL_STATE_SIM_READY;
        } else {
            ESP_LOGE(TAG, "SIM still not ready after PIN");
            s_cell.state = ML_CELL_STATE_ERROR;
            return ESP_ERR_INVALID_STATE;
        }
    } else if (cpin_is(resp, "SIM PUK")) {
        ESP_LOGE(TAG, "SIM is PUK-locked (too many wrong PINs); unlock it in a phone");
        s_pin_guard.blocked = true;
        s_cell.state = ML_CELL_STATE_ERROR;
        return ESP_ERR_NOT_ALLOWED;
    } else if (strstr(resp, "+CPIN:")) {
        ESP_LOGE(TAG, "SIM needs an unsupported code (%.40s)", strstr(resp, "+CPIN:"));
        s_cell.state = ML_CELL_STATE_ERROR;
        return ESP_ERR_NOT_SUPPORTED;
    } else {
        ESP_LOGE(TAG, "SIM not detected — check SIM card insertion");
        s_cell.state = ML_CELL_STATE_ERROR;
        return ESP_ERR_NOT_FOUND;
    }

    /* Get ICCID */
    at_send_cmd("AT+CICCID", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
    at_extract_value(resp, "+ICCID:", s_cell.info.iccid, sizeof(s_cell.info.iccid));
    if (s_cell.info.iccid[0]) {
        char masked[ML_AT_MASKED_ID_SIZE];
        ESP_LOGI(TAG, "ICCID: %s", ml_at_mask_id(s_cell.info.iccid, masked, sizeof(masked)));
        ESP_LOGD(TAG, "ICCID (full): %s", s_cell.info.iccid);
    }

    return ESP_OK;
}

static bool check_registration(const char *resp)
{
    /* Check for ,1 (home) or ,5 (roaming) in AT+CREG/CEREG/CGREG response */
    return strstr(resp, ",1") != NULL || strstr(resp, ",5") != NULL;
}

static esp_err_t network_register(void)
{
    char resp[512];

    ESP_LOGI(TAG, "Waiting for network registration...");

    /* Wait for network registration with timeout.
     * Check both AT+CREG (CS/GSM) and AT+CEREG (EPS/LTE).
     * SIM7600 supports 2G/3G/4G so AT+CREG works, but LTE-only modems
     * like SIM7670G have no CS domain — only AT+CEREG returns registration. */
    int last_creg = -1, last_cereg = -1, last_rssi = 99;
#ifdef CONFIG_ML_CELLULAR_REG_TIMEOUT_S
    const int64_t reg_timeout_s = CONFIG_ML_CELLULAR_REG_TIMEOUT_S;
#else
    const int64_t reg_timeout_s = 180;
#endif
    const int64_t reg_deadline_us = esp_timer_get_time() + reg_timeout_s * 1000000LL;
    for (int i = 0; esp_timer_get_time() < reg_deadline_us; i++) {
        bool registered = false;

        at_send_cmd("AT+CREG?", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
        { char *c = strstr(resp, "+CREG:"); int n, st; if (c && sscanf(c, "+CREG: %d,%d", &n, &st) == 2) last_creg = st; }
        if (check_registration(resp)) {
            registered = true;
            ESP_LOGI(TAG, "CS network registered");
        }

        at_send_cmd("AT+CEREG?", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
        { char *c = strstr(resp, "+CEREG:"); int n, st; if (c && sscanf(c, "+CEREG: %d,%d", &n, &st) == 2) last_cereg = st; }
        if (check_registration(resp)) {
            registered = true;
            ESP_LOGI(TAG, "EPS/LTE network registered");
        } else if (strstr(resp, ",6") != NULL) {
            /* stat=6: registered for SMS only, no data.
             * Known SIM7670G issue with certain SIMs/carriers/firmware. */
            ESP_LOGW(TAG, "EPS registered for SMS only (stat=6) — no data service. "
                     "Check SIM/carrier/APN or update modem firmware.");
        }

        if (!registered && (i % 5) == 4) {
            /* Periodic diagnostics so a stuck registration is explainable. */
            char diag[160];
            at_send_cmd("AT+CSQ", diag, sizeof(diag), AT_SHORT_TIMEOUT_MS);
            { char *c = strstr(diag, "+CSQ:"); int r, b; if (c && sscanf(c, "+CSQ: %d,%d", &r, &b) == 2) last_rssi = r; }
            at_send_cmd("AT+CPSI?", diag, sizeof(diag), AT_SHORT_TIMEOUT_MS);
            char *cpsi = strstr(diag, "+CPSI:");
            if (cpsi) { char *e = strpbrk(cpsi, "\r\n"); if (e) *e = '\0'; }
            ESP_LOGW(TAG, "Still registering: CSQ=%d CREG=%d CEREG=%d %s",
                     last_rssi, last_creg, last_cereg, cpsi ? cpsi : "");
        }

        if (registered) {
            s_cell.info.registered = true;
            s_cell.state = ML_CELL_STATE_REGISTERED;
            ESP_LOGI(TAG, "Network registered");

            /* Get operator name */
            at_send_cmd("AT+COPS?", resp, sizeof(resp), AT_TIMEOUT_MS);
            char *op_start = strstr(resp, "\"");
            if (op_start) {
                op_start++;
                char *op_end = strstr(op_start, "\"");
                if (op_end) {
                    size_t len = (size_t)(op_end - op_start);
                    if (len < sizeof(s_cell.info.operator_name)) {
                        memcpy(s_cell.info.operator_name, op_start, len);
                        s_cell.info.operator_name[len] = '\0';
                        ESP_LOGI(TAG, "Operator: %s", s_cell.info.operator_name);
                    }
                }
            }

            /* Get signal quality */
            at_send_cmd("AT+CSQ", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
            char *csq = strstr(resp, "+CSQ:");
            if (csq) {
                int rssi = 0, ber = 0;
                sscanf(csq, "+CSQ: %d,%d", &rssi, &ber);
                s_cell.info.rssi = rssi;
                s_cell.info.rssi_dbm = (rssi == 99) ? 0 : (-113 + rssi * 2);
                ESP_LOGI(TAG, "Signal: RSSI=%d (%d dBm)", rssi, s_cell.info.rssi_dbm);
            }

            return ESP_OK;
        }

        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    ESP_LOGE(TAG, "Network registration timeout (%lds)", (long)reg_timeout_s);
    if (last_rssi == 99 || last_rssi == 0) {
        ESP_LOGE(TAG, "  No signal (CSQ=%d): check the LTE antenna (MAIN port) and that the modem has a >=2 A supply", last_rssi);
    } else if (last_creg == 3 || last_cereg == 3) {
        ESP_LOGE(TAG, "  Registration DENIED by the network: SIM not activated, plan expired, or roaming not allowed");
    } else {
        ESP_LOGE(TAG, "  Signal CSQ=%d but not registered (CREG=%d CEREG=%d): check SIM plan/coverage/band", last_rssi, last_creg, last_cereg);
    }
    s_cell.state = ML_CELL_STATE_ERROR;
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * PPP Data Connection
 * ========================================================================== */

/* PPP transmit callback — sends data from lwIP PPP stack to SIM7600 UART */
static uint32_t s_ppp_tx_count = 0;

static esp_err_t ppp_transmit(void *h, void *buffer, size_t len)
{
    s_ppp_tx_count++;
    /* Frame dumps include PAP/CHAP exchanges and plaintext DNS: verbose only */
    if (s_ppp_tx_count <= 10 || (s_ppp_tx_count % 20) == 0) {
        ESP_LOGV(TAG, "PPP TX: %d bytes (frame #%lu)", (int)len, (unsigned long)s_ppp_tx_count);
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, buffer, len < 64 ? len : 64, ESP_LOG_VERBOSE);
    }
    uart_write_bytes(UART_NUM, buffer, len);
    return ESP_OK;
}

static esp_netif_driver_ifconfig_t s_ppp_driver_cfg = {
    .handle = (void *)1,   /* Singleton driver, just needs to be != NULL */
    .transmit = ppp_transmit,
};

/* PPP status event handler — detects CHAP auth failure for AT fallback,
 * and PPP close completion (PPPERR_USER) for safe teardown. */
static void ppp_status_event_handler(void *arg, esp_event_base_t event_base,
                                       int32_t event_id, void *event_data)
{
    if (event_id == NETIF_PPP_ERRORUSER) {
        /* ppp_close() completed — safe to destroy netif now */
        ESP_LOGI(TAG, "PPP closed (user interrupt)");
        if (s_cell.ppp_events) {
            xEventGroupSetBits(s_cell.ppp_events, PPP_CLOSED_BIT);
        }
    } else if (event_id == NETIF_PPP_ERRORAUTHFAIL) {
        ESP_LOGW(TAG, "PPP CHAP authentication failed — will fall back to AT");
        if (s_cell.ppp_events) {
            xEventGroupSetBits(s_cell.ppp_events, PPP_CHAP_FAIL_BIT);
        }
    } else if (event_id == NETIF_PPP_ERRORCONNECT) {
        ESP_LOGW(TAG, "PPP connection error");
        if (s_cell.ppp_events) {
            xEventGroupSetBits(s_cell.ppp_events, PPP_CONNECT_FAIL);
        }
    } else if (event_id < NETIF_PP_PHASE_OFFSET && event_id != NETIF_PPP_ERRORNONE) {
        ESP_LOGW(TAG, "PPP error event: %ld", (long)event_id);
        if (s_cell.ppp_events) {
            xEventGroupSetBits(s_cell.ppp_events, PPP_CONNECT_FAIL);
        }
    }
}

/* PPP IP event handler */
static void ppp_ip_event_handler(void *arg, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data)
{
    if (event_id == IP_EVENT_PPP_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        if (event->esp_netif != s_cell.ppp_netif) return;

        ESP_LOGI(TAG, "PPP got IP: " IPSTR, IP2STR(&event->ip_info.ip));

        esp_netif_dns_info_t dns_info;
        esp_netif_get_dns_info(s_cell.ppp_netif, ESP_NETIF_DNS_MAIN, &dns_info);
        ESP_LOGI(TAG, "PPP DNS: " IPSTR, IP2STR(&dns_info.ip.u_addr.ip4));

        s_cell.info.data_connected = true;
        s_cell.state = ML_CELL_STATE_PPP_CONNECTED;
        xEventGroupSetBits(s_cell.ppp_events, PPP_GOT_IP_BIT);
    } else if (event_id == IP_EVENT_GOT_IP6) {
        ip_event_got_ip6_t *event = (ip_event_got_ip6_t *)event_data;
        if (event->esp_netif != s_cell.ppp_netif) return;

        /* Skip link-local (fe80::) — wait for global address */
        if (ip6_addr_islinklocal(&event->ip6_info.ip)) {
            ESP_LOGI(TAG, "PPP got link-local IPv6 (waiting for global)");
            return;
        }

        ESP_LOGI(TAG, "PPP got IPv6: " IPV6STR, IPV62STR(event->ip6_info.ip));
        s_cell.info.data_connected = true;
        s_cell.state = ML_CELL_STATE_PPP_CONNECTED;
        xEventGroupSetBits(s_cell.ppp_events, PPP_GOT_IP6_BIT);
    } else if (event_id == IP_EVENT_PPP_LOST_IP) {
        ESP_LOGW(TAG, "PPP lost IP");
        s_cell.info.data_connected = false;
        s_cell.state = ML_CELL_STATE_REGISTERED;
        xEventGroupSetBits(s_cell.ppp_events, PPP_LOST_IP_BIT);
    }
}

/* PPP receive task — reads UART data from SIM7600 and feeds it to esp_netif */
static void ppp_rx_task(void *arg)
{
    uint8_t *buf = ml_psram_malloc(UART_RX_BUF_SIZE);
    if (!buf) {
        ESP_LOGE(TAG, "Failed to allocate PPP RX buffer");
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "PPP RX task started");

    int rx_frame_count = 0;
    while (s_cell.ppp_running) {
        int len = uart_read_bytes(UART_NUM, buf, UART_RX_BUF_SIZE, pdMS_TO_TICKS(100));
        if (len > 0) {
            rx_frame_count++;
            if (rx_frame_count <= 15) {  /* Log first 15 RX chunks for debugging */
                ESP_LOGD(TAG, "PPP RX: %d bytes (chunk #%d)", len, rx_frame_count);
            }
            esp_netif_receive(s_cell.ppp_netif, buf, len, NULL);
        }
    }

    free(buf);
    ESP_LOGI(TAG, "PPP RX task stopped");
    vTaskDelete(NULL);
}

static esp_err_t ppp_setup_and_dial(void)
{
    char resp[512];

    /* Ensure modem is in clean AT command mode.
     * ATH hangs up any active call/data connection (e.g. leftover PPP from crash).
     * +++ may be needed first if modem is stuck in data mode. */
    at_send_cmd("ATH", resp, sizeof(resp), 5000);
    ESP_LOGI(TAG, "PPP cleanup: ATH -> %.30s", resp);
    vTaskDelay(pdMS_TO_TICKS(500));

    /* Close any existing AT socket bridge session — NETOPEN persists across
     * ESP32 resets and blocks PPP dialing. Ignore errors (not open = OK). */
    at_send_cmd("AT+NETCLOSE", resp, sizeof(resp), 5000);
    ESP_LOGI(TAG, "PPP cleanup: NETCLOSE -> %.30s", resp);
    vTaskDelay(pdMS_TO_TICKS(500));

    /* Deactivate PDP context. If the modem's internal TCP/IP stack previously
     * held CID 1 (from AT+NETOPEN), it won't properly hand the PDP context
     * to PPP — IPCP gets no response because the modem still "owns" the bearer.
     * Deactivating forces ATD*99# to re-establish the PDP context fresh via PPP. */
    at_send_cmd("AT+CGACT=0,1", resp, sizeof(resp), 5000);
    ESP_LOGI(TAG, "PPP cleanup: CGACT=0,1 -> %.30s", resp);

    /* Check current PDP context status for diagnostics */
    at_send_cmd("AT+CGACT?", resp, sizeof(resp), 5000);
    ESP_LOGI(TAG, "PPP cleanup: CGACT? -> %.60s", resp);
    vTaskDelay(pdMS_TO_TICKS(2000));

    /* Configure PDP context — ALWAYS set AT+CGDCONT for PPP.
     * Without an explicit PDP context, the modem has no bearer to bridge
     * over PPP and IPCP will get no response (silent timeout).
     * Empty APN = modem uses network-provided default. */
    const char *ppp_user = s_cell.config.ppp_user ? s_cell.config.ppp_user : "";
    const char *ppp_pass = s_cell.config.ppp_pass ? s_cell.config.ppp_pass : "";
    {
        const char *apn = (s_cell.config.apn && s_cell.config.apn[0])
                          ? s_cell.config.apn : "";
        /* Re-check at the interpolation site: a '"' or CR/LF here would let
         * the value run arbitrary AT commands (ml_cellular_init checks too). */
        if (!ml_at_valid_apn(apn) || !ml_at_valid_credential(ppp_user) ||
            !ml_at_valid_credential(ppp_pass)) {
            ESP_LOGE(TAG, "Invalid APN or PPP credentials; refusing to dial");
            return ESP_ERR_INVALID_ARG;
        }
        char cgdcont_cmd[160];
        snprintf(cgdcont_cmd, sizeof(cgdcont_cmd),
                 "AT+CGDCONT=1,\"IP\",\"%s\"", apn);
        at_cmd_ok(cgdcont_cmd, AT_TIMEOUT_MS);
        if (apn[0]) {
            ESP_LOGI(TAG, "PDP context: APN=%s", apn);
        } else {
            ESP_LOGW(TAG, "PDP context: no APN set (using network default) — "
                     "set APN via menuconfig or web UI for reliable PPP");
        }
    }

    /* Set PDP context authentication.
     * If PPP credentials are provided (e.g. Soracom: sora/sora), use CHAP (type 2).
     * Otherwise use PAP with empty credentials (type 1) — EIOT/BICS SIMs pass
     * PAP Auth-Ack with empty creds (IMSI-based auth). */
    {
        /* Auth type: 0=none, 1=PAP, 2=CHAP */
        int auth_type = (ppp_user[0] || ppp_pass[0]) ? 2 : 1;  /* CHAP if creds, PAP if empty */
        char auth_cmd[192];   /* 2 x ML_AT_CRED_MAX + command: never truncated */
        /* SIMCom order is password first: AT+CGAUTH=<cid>,<auth_type>,
         * <passwd>,<user> (SIM7500/SIM7600 AT manual V3.00 and A7600
         * series AT manual V1.01, which covers the A76xx/SIM767x family),
         * unlike 3GPP TS 27.007's <username>,<password>. */
        snprintf(auth_cmd, sizeof(auth_cmd),
                 "AT+CGAUTH=1,%d,\"%s\",\"%s\"", auth_type, ppp_pass, ppp_user);
        at_cmd_ok(auth_cmd, AT_TIMEOUT_MS);
        ml_at_secure_zero(auth_cmd, sizeof(auth_cmd));
    }
    if (ppp_user[0] || ppp_pass[0]) {
        ESP_LOGI(TAG, "PPP credentials set (CHAP)");
    } else {
        ESP_LOGI(TAG, "PPP: empty credentials, PAP auth (IMSI-based)");
    }

    /* Do NOT activate PDP context here (AT+CGACT=1,1) — let ATD*99***1#
     * activate it during PPP negotiation. Pre-activating can cause the modem's
     * internal TCP/IP stack to claim the context, blocking IPCP. */

    /* Create PPP netif */
    s_cell.ppp_events = xEventGroupCreate();
    if (!s_cell.ppp_events) {
        ESP_LOGE(TAG, "Failed to create PPP event group");
        return ESP_ERR_NO_MEM;
    }

    /* Register IP event handler */
    esp_err_t err = esp_event_handler_instance_register(
        IP_EVENT, ESP_EVENT_ANY_ID,
        ppp_ip_event_handler, NULL,
        &s_cell.ip_event_handler);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register IP event handler: %s", esp_err_to_name(err));
        return err;
    }

    /* Create PPP network interface */
    esp_netif_inherent_config_t base_cfg = ESP_NETIF_INHERENT_DEFAULT_PPP();
    base_cfg.if_desc = "ml_ppp";
    base_cfg.route_prio = 10;   /* Lower priority than WiFi (default 100) initially */

    esp_netif_config_t ppp_config = {
        .base = &base_cfg,
        .driver = &s_ppp_driver_cfg,
        .stack = ESP_NETIF_NETSTACK_DEFAULT_PPP,
    };

    s_cell.ppp_netif = esp_netif_new(&ppp_config);
    if (!s_cell.ppp_netif) {
        ESP_LOGE(TAG, "Failed to create PPP netif");
        return ESP_FAIL;
    }

    /* Set PPP authentication — CHAP if credentials provided, PAP if empty */
    esp_netif_auth_type_t auth = (ppp_user[0] || ppp_pass[0])
                                 ? NETIF_PPP_AUTHTYPE_CHAP
                                 : NETIF_PPP_AUTHTYPE_PAP;
    esp_netif_ppp_set_auth(s_cell.ppp_netif, auth, ppp_user, ppp_pass);

    /* Enable PPP error events for CHAP failure detection */
    esp_netif_ppp_config_t ppp_evt_cfg = {
        .ppp_phase_event_enabled = false,
        .ppp_error_event_enabled = true,
    };
    esp_netif_ppp_set_params(s_cell.ppp_netif, &ppp_evt_cfg);

    /* Register PPP status event handler (CHAP failure, connection errors) */
    esp_event_handler_instance_register(
        NETIF_PPP_STATUS, ESP_EVENT_ANY_ID,
        ppp_status_event_handler, NULL,
        &s_cell.ppp_status_handler);

    ESP_LOGI(TAG, "PPP %s auth configured", (ppp_user[0] || ppp_pass[0]) ? "CHAP" : "PAP");

    /* Do NOT call esp_netif_action_start() yet — it immediately sends LCP
     * Configure-Request frames via ppp_transmit(), which would go to the modem
     * while it's still in AT command mode and corrupt the AT session. */

    /* Dial PPP data mode — ATD*99***1# specifies PDP context 1 explicitly.
     * Retry up to 3 times: modem PDP deactivation is async and carrier-dependent,
     * sometimes the first dial fails with ERROR even after CGACT=0,1 + delay. */
    ESP_LOGI(TAG, "Dialing PPP (ATD*99***1#)...");
    s_cell.state = ML_CELL_STATE_PPP_CONNECTING;

    bool dial_ok = false;
    for (int attempt = 1; attempt <= 4; attempt++) {
        at_send_cmd("ATD*99***1#", resp, sizeof(resp), 15000);
        if (strstr(resp, "CONNECT")) {
            dial_ok = true;
            break;
        }
        ESP_LOGW(TAG, "PPP dial attempt %d/4 failed: %.30s", attempt, resp);
        if (attempt < 4) {
            /* Escalating recovery between retries:
             * 1→2: hangup + PDP deactivate + 3s
             * 2→3: hangup + PDP deactivate + 5s
             * 3→4: full CFUN reset + 8s */
            at_send_cmd("ATH", resp, sizeof(resp), 5000);
            at_send_cmd("AT+CGACT=0,1", resp, sizeof(resp), 5000);
            if (attempt >= 3) {
                /* Nuclear option: CFUN=0 (minimum functionality) then CFUN=1 (full) */
                ESP_LOGW(TAG, "PPP dial: CFUN reset on attempt %d", attempt);
                at_send_cmd("AT+CFUN=0", resp, sizeof(resp), 10000);
                vTaskDelay(pdMS_TO_TICKS(2000));
                at_send_cmd("AT+CFUN=1", resp, sizeof(resp), 10000);
                vTaskDelay(pdMS_TO_TICKS(8000));
                /* Re-check registration after CFUN reset */
                at_send_cmd("AT+CEREG?", resp, sizeof(resp), 5000);
                ESP_LOGI(TAG, "Post-CFUN: CEREG -> %.40s", resp);
            } else {
                int delay_ms = (attempt == 1) ? 3000 : 5000;
                vTaskDelay(pdMS_TO_TICKS(delay_ms));
            }
        }
    }
    if (!dial_ok) {
        ESP_LOGE(TAG, "PPP dial failed (3 attempts)");
        s_cell.state = ML_CELL_STATE_ERROR;
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "PPP CONNECT received, starting PPP...");

    /* Modem is now in PPP data mode. Start the RX task FIRST so it's ready
     * to receive LCP frames as soon as we kick off the PPP state machine. */
    s_cell.ppp_running = true;
    BaseType_t ret = xTaskCreatePinnedToCore(
        ppp_rx_task, "ml_ppp_rx", 4096, NULL,
        5, &s_cell.ppp_task, 0);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create PPP RX task");
        s_cell.ppp_running = false;
        s_cell.state = ML_CELL_STATE_ERROR;
        return ESP_FAIL;
    }

    /* Small delay to let RX task settle and start reading UART */
    vTaskDelay(pdMS_TO_TICKS(50));

    /* NOW start the PPP protocol — this sends the first LCP Configure-Request.
     * The modem is already in data mode, and the RX task is ready to receive. */
    esp_netif_action_start(s_cell.ppp_netif, 0, 0, 0);
    esp_netif_action_connected(s_cell.ppp_netif, 0, 0, 0);

    /* Wait for IP assignment, CHAP failure, or timeout */
    EventBits_t bits = xEventGroupWaitBits(
        s_cell.ppp_events,
        PPP_GOT_IP_BIT | PPP_GOT_IP6_BIT | PPP_CONNECT_FAIL | PPP_CHAP_FAIL_BIT,
        pdFALSE, pdFALSE,
        pdMS_TO_TICKS(PPP_CONNECT_TIMEOUT_MS));

    if (bits & (PPP_GOT_IP_BIT | PPP_GOT_IP6_BIT)) {
        ESP_LOGI(TAG, "PPP data connection established (%s)",
                 (bits & PPP_GOT_IP_BIT) ? "IPv4" : "IPv6");
        return ESP_OK;
    }

    if (bits & PPP_CHAP_FAIL_BIT) {
        ESP_LOGW(TAG, "PPP CHAP authentication failed");
        s_cell.ppp_running = false;
        vTaskDelay(pdMS_TO_TICKS(200));
        s_cell.state = ML_CELL_STATE_REGISTERED;
        return ESP_ERR_NOT_SUPPORTED;   /* Distinct from timeout — caller can fall back */
    }

    ESP_LOGE(TAG, "PPP connection timeout");
    if (!s_cell.config.apn || s_cell.config.apn[0] == '\0') {
        ESP_LOGE(TAG, "  No APN configured: set CONFIG_ML_CELLULAR_APN (e.g. soracom.io) for your SIM");
    }
    s_cell.ppp_running = false;
    vTaskDelay(pdMS_TO_TICKS(200)); /* Let RX task exit */
    s_cell.state = ML_CELL_STATE_ERROR;
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

/* Copy a validated config string into driver-owned storage (NULL stays NULL) */
static const char *copy_config_str(char *dst, size_t dst_size, const char *src)
{
    if (!src) {
        dst[0] = '\0';
        return NULL;
    }
    strlcpy(dst, src, dst_size);
    return dst;
}

static void clear_config_strs(void)
{
    ml_at_secure_zero(s_cell.sim_pin, sizeof(s_cell.sim_pin));
    ml_at_secure_zero(s_cell.ppp_user, sizeof(s_cell.ppp_user));
    ml_at_secure_zero(s_cell.ppp_pass, sizeof(s_cell.ppp_pass));
    s_cell.apn[0] = '\0';
    s_cell.config.apn = NULL;
    s_cell.config.sim_pin = NULL;
    s_cell.config.ppp_user = NULL;
    s_cell.config.ppp_pass = NULL;
}

/* Switch modem and UART to fast_baud; on failure fall back to base_baud.
 * Caller holds s_uart_lock. */
static esp_err_t fast_baud_switch_locked(int fast_baud, int base_baud)
{
    char ipr_cmd[32];
    snprintf(ipr_cmd, sizeof(ipr_cmd), "AT+IPR=%d", fast_baud);
    if (at_cmd_ok_locked(ipr_cmd, AT_SHORT_TIMEOUT_MS)) {
        vTaskDelay(pdMS_TO_TICKS(100));
        /* Reconfigure ESP32 UART to match */
        uart_set_baudrate(UART_NUM, fast_baud);
        vTaskDelay(pdMS_TO_TICKS(100));
        /* Verify communication at new baud rate */
        if (at_cmd_ok_locked("AT", AT_SHORT_TIMEOUT_MS)) {
            s_cell.config.baud_rate = fast_baud;
            ESP_LOGI(TAG, "UART baud rate upgraded: 115200 -> %d", fast_baud);
        } else {
            /* The modem is now at fast_baud (and AT+IPR persists), so the
             * revert must be sent at fast_baud: replies may be garbled but
             * the command usually gets through. Then return to base_baud. */
            ESP_LOGW(TAG, "Fast baud %d failed, reverting to %d", fast_baud, base_baud);
            char revert[32];
            int rlen = snprintf(revert, sizeof(revert), "AT+IPR=%d\r", base_baud);
            for (int r = 0; r < 3; r++) {
                uart_write_bytes(UART_NUM, revert, rlen);
                vTaskDelay(pdMS_TO_TICKS(150));
            }
            uart_set_baudrate(UART_NUM, base_baud);
            vTaskDelay(pdMS_TO_TICKS(200));
            uart_flush_input(UART_NUM);
            if (!at_cmd_ok_locked("AT", AT_SHORT_TIMEOUT_MS)) {
                ESP_LOGE(TAG, "Modem not responding after baud revert; its baud "
                              "rate is re-detected (and normalised) on the next init");
                return ESP_ERR_TIMEOUT;
            }
        }
    }
    return ESP_OK;
}

/* Undo a failed ml_cellular_init() after the UART was installed. s_cell.info
 * is kept for diagnostics (it is reset by the next init). */
static void init_failed_cleanup(void)
{
    bool locked = ml_cellular_uart_lock();
    if (s_cell.uart_installed) {
        s_cell.uart_installed = false;
        uart_driver_delete(UART_NUM);
    }
    clear_config_strs();
    s_cell.data_mode = ML_DATA_MODE_NONE;
    s_cell.state = ML_CELL_STATE_OFF;
    if (locked) ml_cellular_uart_unlock();
}

/* Power up the modem and bring it to REGISTERED (UART already installed) */
static esp_err_t modem_bringup(void)
{
    esp_err_t err;

    /* Board-specific modem power-on sequence.
     * Use gpio_config() instead of gpio_set_direction() for reliable GPIO init
     * on all ESP32-S3 boards (ref: LilyGO Issue #220). */
#if CONFIG_ML_CELLULAR_PWRKEY_PIN >= 0
    ESP_LOGI(TAG, "Modem power-on: PWRKEY pulse on GPIO%d", CONFIG_ML_CELLULAR_PWRKEY_PIN);
    gpio_config_t pwrkey_conf = {
        .pin_bit_mask = (1ULL << CONFIG_ML_CELLULAR_PWRKEY_PIN),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&pwrkey_conf);
    gpio_set_level(CONFIG_ML_CELLULAR_PWRKEY_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level(CONFIG_ML_CELLULAR_PWRKEY_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(1000));
    gpio_set_level(CONFIG_ML_CELLULAR_PWRKEY_PIN, 1);
#endif
#if CONFIG_ML_CELLULAR_DTR_PIN >= 0
    gpio_config_t dtr_conf = {
        .pin_bit_mask = (1ULL << CONFIG_ML_CELLULAR_DTR_PIN),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&dtr_conf);
    gpio_set_level(CONFIG_ML_CELLULAR_DTR_PIN, 0);
#endif

    /* Wait for modem to respond.
     * SIM7670G boots slower than SIM7600 (5-15s vs 3-5s). */
#ifdef CONFIG_ML_BOARD_LILYGO_T_SIM7670G
    ESP_LOGI(TAG, "Waiting 5s for SIM7670G boot...");
    vTaskDelay(pdMS_TO_TICKS(5000));
#else
    ESP_LOGI(TAG, "Waiting 3s for modem boot...");
    vTaskDelay(pdMS_TO_TICKS(3000));
#endif

    err = modem_wait_ready();
    if (err != ESP_OK) return err;

    /* Get module info (IMEI, model, firmware) */
    err = modem_setup();
    if (err != ESP_OK) return err;

    /* Upgrade UART baud rate for faster data transfer.
     * Start at 115200 for reliable initial handshake, then switch to a higher
     * rate. SIM7670G lacks hardware flow control on most boards and has smaller
     * UART buffers — cap at 115200 to avoid data loss. SIM7600 handles 921600. */
#if defined(CONFIG_ML_BOARD_LILYGO_T_SIM7670G) || !defined(CONFIG_ML_CELLULAR_FAST_BAUD)
    int fast_baud = 0;  /* SIM7670G unreliable above 115200 without flow control */
#else
    /* Opt-in: without hardware flow control and short wiring, 921600 often
     * fails (seen on SIM7600G-H with jumper wires and on A7670E). */
    int fast_baud = CONFIG_ML_CELLULAR_FAST_BAUD;
#endif
    const int base_baud = s_cell.config.baud_rate;
    if (fast_baud && fast_baud != base_baud) {
        /* The whole switch runs under the UART lock: a command from another
         * task in the middle would go out at the wrong rate. */
        if (!ml_cellular_uart_lock()) return ESP_ERR_INVALID_STATE;
        err = fast_baud_switch_locked(fast_baud, base_baud);
        ml_cellular_uart_unlock();
        if (err != ESP_OK) return err;
    }

    /* Setup SIM card (check status, enter PIN if needed) */
    err = sim_setup();
    if (err != ESP_OK) return err;

    /* Wait for network registration */
    err = network_register();
    if (err != ESP_OK) return err;

    char masked_imei[ML_AT_MASKED_ID_SIZE];
    ESP_LOGI(TAG, "Cellular modem ready: %s IMEI=%s Operator=%s RSSI=%d",
             s_cell.info.model, ml_at_mask_id(s_cell.info.imei, masked_imei, sizeof(masked_imei)),
             s_cell.info.operator_name, s_cell.info.rssi);

    return ESP_OK;
}

esp_err_t ml_cellular_init(const ml_cellular_config_t *config)
{
    if (s_cell.state != ML_CELL_STATE_OFF) {
        ESP_LOGW(TAG, "Already initialized");
        return ESP_ERR_INVALID_STATE;
    }

    /* Apply config or defaults */
    if (config) {
        s_cell.config = *config;
    } else {
        ml_cellular_config_t def = ML_CELLULAR_DEFAULT_CONFIG();
        s_cell.config = def;
    }

    /* Reject values that cannot be passed safely inside an AT command
     * (Kconfig, NVS and application config all arrive here). */
    {
        const char *bad = NULL;
        if (s_cell.config.apn && !ml_at_valid_apn(s_cell.config.apn)) {
            bad = "APN (letters, digits, '-' and '.', max 100)";
        } else if (s_cell.config.sim_pin && s_cell.config.sim_pin[0] &&
                   !ml_at_valid_pin(s_cell.config.sim_pin)) {
            bad = "SIM PIN (4-8 digits)";
        } else if (s_cell.config.ppp_user && !ml_at_valid_credential(s_cell.config.ppp_user)) {
            bad = "PPP user (printable ASCII without '\"' or '\\', max 64)";
        } else if (s_cell.config.ppp_pass && !ml_at_valid_credential(s_cell.config.ppp_pass)) {
            bad = "PPP password (printable ASCII without '\"' or '\\', max 64)";
        }
        if (bad) {
            ESP_LOGE(TAG, "Invalid cellular config: %s", bad);
            return ESP_ERR_INVALID_ARG;
        }
    }

    /* Keep our own copies: the PPP credentials are handed to lwIP
     * (ppp_set_auth() stores the pointers) and used again on a CHAP
     * re-challenge long after the caller's buffers are gone. The lengths
     * were checked above, so nothing is truncated. */
    s_cell.config.apn = copy_config_str(s_cell.apn, sizeof(s_cell.apn), s_cell.config.apn);
    s_cell.config.sim_pin = copy_config_str(s_cell.sim_pin, sizeof(s_cell.sim_pin),
                                            s_cell.config.sim_pin);
    s_cell.config.ppp_user = copy_config_str(s_cell.ppp_user, sizeof(s_cell.ppp_user),
                                             s_cell.config.ppp_user);
    s_cell.config.ppp_pass = copy_config_str(s_cell.ppp_pass, sizeof(s_cell.ppp_pass),
                                             s_cell.config.ppp_pass);

    if (!s_uart_lock) {
        s_uart_lock = xSemaphoreCreateMutex();
        if (!s_uart_lock) {
            clear_config_strs();
            return ESP_ERR_NO_MEM;
        }
    }

    if (s_cell.config.tx_pin == 0) s_cell.config.tx_pin = 43;
    if (s_cell.config.rx_pin == 0) s_cell.config.rx_pin = 44;
    if (s_cell.config.baud_rate == 0) s_cell.config.baud_rate = 115200;

    memset(&s_cell.info, 0, sizeof(s_cell.info));
    s_cell.state = ML_CELL_STATE_INIT;

    /* Initialize UART */
    esp_err_t err = uart_init();
    if (err != ESP_OK) {
        clear_config_strs();
        s_cell.state = ML_CELL_STATE_OFF;
        return err;
    }

    err = modem_bringup();
    if (err != ESP_OK) {
        /* Leave nothing behind, so the next ml_cellular_init() starts from
         * scratch instead of failing with "Already initialized". */
        init_failed_cleanup();
    }
    return err;
}

void ml_cellular_deinit(void)
{
    if (s_cell.state == ML_CELL_STATE_OFF) return;

    /* The AT socket bridge sends commands on the UART: stop it before the
     * driver goes away (no-op unless the bridge is active). */
    ml_cellular_data_stop();

    /* Stop PPP if running (or half set up after a failed dial) */
    if (s_cell.ppp_running || s_cell.ppp_netif) {
        ml_cellular_ppp_stop();
    }

    /* An application task may be inside ml_cellular_send_at_cmd(), blocked
     * in uart_read_bytes() with the UART lock held. Deleting the driver
     * under it frees the ring buffer and semaphores it is waiting on, so
     * wait for the lock. Commands that arrive later find uart_installed
     * false and fail cleanly. */
    bool locked = ml_cellular_uart_lock();
    if (s_cell.uart_installed) {
        s_cell.uart_installed = false;
        uart_driver_delete(UART_NUM);
    }
    memset(&s_cell.info, 0, sizeof(s_cell.info));
    clear_config_strs();
    s_cell.data_mode = ML_DATA_MODE_NONE;
    s_cell.state = ML_CELL_STATE_OFF;
    if (locked) ml_cellular_uart_unlock();
    ESP_LOGI(TAG, "Cellular deinitialized");
}

esp_err_t ml_cellular_ppp_start(void)
{
    if (s_cell.state != ML_CELL_STATE_REGISTERED) {
        ESP_LOGE(TAG, "Cannot start PPP: not registered (state=%d)", s_cell.state);
        return ESP_ERR_INVALID_STATE;
    }

    return ppp_setup_and_dial();
}

esp_err_t ml_cellular_ppp_stop(void)
{
    if (!s_cell.ppp_running && !s_cell.ppp_netif) return ESP_OK;

    ESP_LOGI(TAG, "Stopping PPP...");

    /* 1. Stop RX task — no more UART reads feeding lwIP */
    s_cell.ppp_running = false;
    vTaskDelay(pdMS_TO_TICKS(500)); /* Let task exit cleanly */

    /* 2. Initiate PPP close via esp_netif.
     *    esp_netif_action_stop → ppp_close(0) which is ASYNCHRONOUS —
     *    the lwIP TCPIP thread runs the LCP termination FSM, and
     *    eventually calls on_ppp_status_changed(PPPERR_USER).
     *    We MUST wait for that callback before destroying the netif,
     *    otherwise the TCPIP thread accesses freed memory and crashes. */
    if (s_cell.ppp_netif) {
        /* Clear any previous bits so we get a clean wait */
        if (s_cell.ppp_events) {
            xEventGroupClearBits(s_cell.ppp_events, PPP_CLOSED_BIT);
        }

        /* Mark interface down, then initiate ppp_close */
        esp_netif_action_disconnected(s_cell.ppp_netif, 0, 0, 0);
        esp_netif_action_stop(s_cell.ppp_netif, 0, 0, 0);

        /* Wait for PPP close to complete on the TCPIP thread.
         * The ppp_status_event_handler sets PPP_CLOSED_BIT on PPPERR_USER.
         * LCP terminate has retransmit timeouts, so this can take several seconds. */
        if (s_cell.ppp_events) {
            ESP_LOGI(TAG, "Waiting for PPP close callback...");
            EventBits_t bits = xEventGroupWaitBits(
                s_cell.ppp_events, PPP_CLOSED_BIT,
                pdFALSE, pdFALSE,
                pdMS_TO_TICKS(15000));  /* 15s timeout for LCP terminate retransmits */
            if (bits & PPP_CLOSED_BIT) {
                ESP_LOGI(TAG, "PPP close confirmed");
            } else {
                ESP_LOGW(TAG, "PPP close timeout — proceeding with teardown");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(100)); /* Brief settle after close */
    }

    /* 3. Unregister event handlers — PPP FSM is fully stopped now */
    if (s_cell.ppp_status_handler) {
        esp_event_handler_instance_unregister(NETIF_PPP_STATUS, ESP_EVENT_ANY_ID, s_cell.ppp_status_handler);
        s_cell.ppp_status_handler = NULL;
    }
    if (s_cell.ip_event_handler) {
        esp_event_handler_instance_unregister(IP_EVENT, ESP_EVENT_ANY_ID, s_cell.ip_event_handler);
        s_cell.ip_event_handler = NULL;
    }

    /* 4. Destroy netif */
    if (s_cell.ppp_netif) {
        esp_netif_destroy(s_cell.ppp_netif);
        s_cell.ppp_netif = NULL;
    }

    if (s_cell.ppp_events) {
        vEventGroupDelete(s_cell.ppp_events);
        s_cell.ppp_events = NULL;
    }

    /* 5. Escape PPP data mode → AT command mode via Hayes +++ (under the
     *    UART lock, so nothing is sent during the guard times), then hang up */
    if (ml_cellular_uart_lock()) {
        escape_data_mode_locked();
        char resp[256];
        at_send_cmd_locked("AT", resp, sizeof(resp), AT_SHORT_TIMEOUT_MS);
        at_cmd_ok_locked("ATH", AT_TIMEOUT_MS);
        ml_cellular_uart_unlock();
    }

    s_cell.info.data_connected = false;
    if (s_cell.info.registered) {
        s_cell.state = ML_CELL_STATE_REGISTERED;
    } else {
        s_cell.state = ML_CELL_STATE_AT_OK;
    }

    ESP_LOGI(TAG, "PPP stopped, returned to AT mode");
    return ESP_OK;
}

ml_cellular_state_t ml_cellular_get_state(void)
{
    return s_cell.state;
}

esp_err_t ml_cellular_get_info(ml_cellular_info_t *info)
{
    if (!info) return ESP_ERR_INVALID_ARG;
    *info = s_cell.info;
    return ESP_OK;
}

const char *ml_cellular_get_imei(void)
{
    return s_cell.info.imei[0] ? s_cell.info.imei : NULL;
}

int ml_cellular_send_at_cmd(const char *cmd, char *response, size_t resp_size, int timeout_ms)
{
    char log_cmd[48];

    if (!response || resp_size < 2) return -1;
    response[0] = '\0';
    if (!ml_at_cmd_is_safe(cmd, 0)) {
        ESP_LOGW(TAG, "send_at_cmd: rejected (must be one line starting with AT, "
                 "printable ASCII, max %d chars)", ML_AT_CMD_MAX);
        return -1;
    }
    if (timeout_ms <= 0) timeout_ms = AT_TIMEOUT_MS;
    if (timeout_ms > ML_CELLULAR_AT_CMD_MAX_TIMEOUT_MS) timeout_ms = ML_CELLULAR_AT_CMD_MAX_TIMEOUT_MS;

    if (!ml_cellular_uart_lock()) {
        ESP_LOGW(TAG, "send_at_cmd: modem not initialized");
        return -1;
    }

    /* State is checked under the lock so it cannot change underneath us
     * (e.g. the PPP dial switching the UART to data mode). */
    int ret = -1;
    ml_cellular_state_t st = s_cell.state;
    if (!s_cell.uart_installed) {
        ESP_LOGW(TAG, "send_at_cmd: modem not initialized");
    } else if (s_cell.ppp_running || st == ML_CELL_STATE_PPP_CONNECTING ||
               st == ML_CELL_STATE_PPP_CONNECTED) {
        ESP_LOGW(TAG, "send_at_cmd: UART is in PPP data mode; AT commands are not available "
                 "(use CONFIG_ML_CELLULAR_DATA_AT_ONLY or the modem's AUX/USB port)");
    } else if (st == ML_CELL_STATE_DATA_CONNECTED) {
        if (!ml_at_cmd_allowed_with_bridge(cmd)) {
            ESP_LOGW(TAG, "send_at_cmd: '%s' not allowed while the AT socket bridge is active",
                     ml_at_redact_cmd(cmd, log_cmd, sizeof(log_cmd)));
        } else {
            ret = ml_at_socket_cmd_locked(cmd, response, resp_size, timeout_ms);
        }
    } else {
        ret = at_send_cmd_locked(cmd, response, resp_size, timeout_ms);
    }

    ml_cellular_uart_unlock();
    return ret;
}

int ml_cellular_send_at(const char *cmd, char *response, size_t resp_size, int timeout_ms)
{
    return ml_cellular_send_at_cmd(cmd, response, resp_size, timeout_ms);
}

/* ============================================================================
 * AT Socket Bridge Data Mode (bypasses PPP, uses modem internal TCP/IP)
 * ========================================================================== */

esp_err_t ml_cellular_data_start(void)
{
    if (s_cell.state < ML_CELL_STATE_REGISTERED) {
        ESP_LOGE(TAG, "Cannot start data mode — not registered on network (state=%d)", s_cell.state);
        return ESP_ERR_INVALID_STATE;
    }

    if (s_cell.ppp_running) {
        ESP_LOGW(TAG, "PPP is running — stop it first");
        return ESP_ERR_INVALID_STATE;
    }

    if (s_cell.state == ML_CELL_STATE_DATA_CONNECTED) {
        ESP_LOGW(TAG, "AT socket bridge already active");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Starting AT socket bridge data mode...");

    /* Initialize the AT socket bridge (sends AT+NETOPEN, starts URC handler) */
    esp_err_t ret = ml_at_socket_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "AT socket bridge init failed: %s", esp_err_to_name(ret));
        s_cell.state = ML_CELL_STATE_ERROR;
        return ret;
    }

    s_cell.state = ML_CELL_STATE_DATA_CONNECTED;
    s_cell.info.data_connected = true;
    ESP_LOGI(TAG, "AT socket bridge data mode ACTIVE");
    return ESP_OK;
}

esp_err_t ml_cellular_data_stop(void)
{
    if (s_cell.state != ML_CELL_STATE_DATA_CONNECTED) {
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Stopping AT socket bridge data mode...");

    ml_at_socket_deinit();

    s_cell.info.data_connected = false;
    if (s_cell.info.registered) {
        s_cell.state = ML_CELL_STATE_REGISTERED;
    } else {
        s_cell.state = ML_CELL_STATE_AT_OK;
    }

    ESP_LOGI(TAG, "AT socket bridge stopped");
    return ESP_OK;
}

bool ml_cellular_is_data_mode(void)
{
    return s_cell.state == ML_CELL_STATE_DATA_CONNECTED;
}

esp_err_t ml_cellular_connect(void)
{
    if (s_cell.state < ML_CELL_STATE_REGISTERED) {
        ESP_LOGE(TAG, "Cannot connect data: not registered on network (state=%d)",
                 s_cell.state);
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t ret;

#ifdef CONFIG_ML_CELLULAR_DATA_AT_ONLY
    /* AT socket only — skip PPP, keep UART in AT command mode */
    ESP_LOGI(TAG, "=== Starting AT socket bridge (AT-only mode) ===");
    ret = ml_cellular_data_start();
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "AT socket bridge connected — UART remains in AT command mode");
        s_cell.data_mode = ML_DATA_MODE_AT_SOCKET;
        return ESP_OK;
    }
    ESP_LOGE(TAG, "AT socket bridge failed");
    s_cell.data_mode = ML_DATA_MODE_NONE;
    return ret;

#elif defined(CONFIG_ML_CELLULAR_DATA_PPP_ONLY)
    /* PPP only — no AT socket fallback */
    ESP_LOGI(TAG, "=== Attempting PPP data connection (PPP-only mode) ===");
    ret = ml_cellular_ppp_start();
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "PPP connected — using lwIP standard sockets");
        s_cell.data_mode = ML_DATA_MODE_PPP;
        return ESP_OK;
    }
    ESP_LOGE(TAG, "PPP failed: %s", esp_err_to_name(ret));
    ml_cellular_ppp_stop();
    s_cell.data_mode = ML_DATA_MODE_NONE;
    return ret;

#else
    /* Auto: try PPP first, fall back to AT socket bridge */
    ESP_LOGI(TAG, "=== Attempting PPP data connection ===");
    ret = ml_cellular_ppp_start();

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "PPP connected — using lwIP standard sockets");
        s_cell.data_mode = ML_DATA_MODE_PPP;
        return ESP_OK;
    }

    /* PPP failed — clean up and fall back to AT socket bridge */
    ESP_LOGW(TAG, "PPP failed (%s) — falling back to AT socket bridge",
             esp_err_to_name(ret));
    ml_cellular_ppp_stop();

    /* Brief delay for modem to settle after exiting PPP data mode */
    vTaskDelay(pdMS_TO_TICKS(2000));

    /* --- Fall back to AT socket bridge --- */
    ESP_LOGI(TAG, "=== Starting AT socket bridge (fallback) ===");
    ret = ml_cellular_data_start();

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "AT socket bridge connected — using modem internal TCP/IP");
        s_cell.data_mode = ML_DATA_MODE_AT_SOCKET;
        return ESP_OK;
    }

    ESP_LOGE(TAG, "Both PPP and AT socket bridge failed");
    s_cell.data_mode = ML_DATA_MODE_NONE;
    return ret;
#endif
}

ml_cellular_data_mode_t ml_cellular_get_data_mode(void)
{
    return s_cell.data_mode;
}

#endif /* CONFIG_ML_ENABLE_CELLULAR */
