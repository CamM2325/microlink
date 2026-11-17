/**
 * @file ml_cellular.h
 * @brief MicroLink Cellular Module — SIM7600 4G Modem Driver
 *
 * Provides AT command interface to SIM7600G-H cellular modem over UART,
 * plus PPP data connection that creates an esp_netif PPP interface for lwIP.
 *
 * Hardware: Seeed Studio XIAO ESP32S3 + Waveshare SIM7600X 4G Module
 * Wiring:
 *   SIM7600 TXD  →  XIAO D7 (GPIO44 / RX)
 *   SIM7600 RXD  →  XIAO D6 (GPIO43 / TX)
 *   GND connected, separate USB-C power supplies
 */

#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ========================================================================== */

/* ml_cellular_init() copies the strings, so the caller's buffers need not
 * outlive the call. */
typedef struct {
    int tx_pin;                 /* ESP32 TX → SIM7600 RXD (default: GPIO43) */
    int rx_pin;                 /* ESP32 RX ← SIM7600 TXD (default: GPIO44) */
    int baud_rate;              /* UART baud rate (default: 115200) */
    const char *apn;            /* APN for data connection (NULL = auto) */
    const char *sim_pin;        /* SIM PIN code (NULL = no PIN required). Sent
                                 * at most once until accepted: see
                                 * ml_cellular_sim_pin_blocked() */
    const char *ppp_user;       /* PPP CHAP username (NULL = empty) */
    const char *ppp_pass;       /* PPP CHAP password (NULL = empty) */
} ml_cellular_config_t;

/* Default pin configuration for XIAO ESP32S3 + Waveshare SIM7600X */
#define ML_CELLULAR_DEFAULT_CONFIG() { \
    .tx_pin = 43,               \
    .rx_pin = 44,               \
    .baud_rate = 115200,        \
    .apn = NULL,                \
    .sim_pin = NULL,            \
    .ppp_user = NULL,           \
    .ppp_pass = NULL,           \
}

/* ============================================================================
 * Cellular state
 * ========================================================================== */

typedef enum {
    ML_CELL_STATE_OFF,          /* Not initialized */
    ML_CELL_STATE_INIT,         /* UART initialized, AT communication pending */
    ML_CELL_STATE_AT_OK,        /* AT communication established */
    ML_CELL_STATE_SIM_READY,    /* SIM card ready */
    ML_CELL_STATE_REGISTERED,   /* Registered on network */
    ML_CELL_STATE_PPP_CONNECTING, /* PPP dial in progress */
    ML_CELL_STATE_PPP_CONNECTED,  /* PPP connected, IP assigned */
    ML_CELL_STATE_DATA_CONNECTED, /* AT socket bridge connected (modem internal TCP/IP) */
    ML_CELL_STATE_ERROR,        /* Error state */
} ml_cellular_state_t;

typedef enum {
    ML_DATA_MODE_NONE,          /* No data connection */
    ML_DATA_MODE_PPP,           /* PPP — standard lwIP sockets */
    ML_DATA_MODE_AT_SOCKET,     /* AT socket bridge — modem internal TCP/IP */
} ml_cellular_data_mode_t;

/* ============================================================================
 * Module info
 * ========================================================================== */

typedef struct {
    char imei[20];              /* IMEI string (15 digits + null) */
    char iccid[24];             /* SIM ICCID */
    char model[32];             /* Module model (e.g. "SIM7600G-H") */
    char firmware[64];          /* Firmware version */
    char operator_name[32];     /* Registered operator */
    int rssi;                   /* Signal strength (0-31, 99=unknown) */
    int rssi_dbm;               /* Signal in dBm */
    bool sim_ready;             /* SIM card is ready */
    bool registered;            /* Registered on network */
    bool data_connected;        /* PPP data connection active */
} ml_cellular_info_t;

/* ============================================================================
 * Public API
 * ========================================================================== */

/**
 * Initialize the SIM7600 cellular modem.
 * Sets up UART, sends initial AT commands, checks SIM status.
 * Does NOT start PPP data connection.
 *
 * On failure the UART is released and the driver is back in state OFF, so
 * the call can simply be retried (no ml_cellular_deinit() needed).
 *
 * @param config  Cellular configuration (NULL for defaults)
 * @return ESP_OK on success
 */
esp_err_t ml_cellular_init(const ml_cellular_config_t *config);

/**
 * Deinitialize cellular module. Stops the AT socket bridge and PPP if
 * active, waits for an in-flight ml_cellular_send_at_cmd() to finish,
 * then releases the UART.
 */
void ml_cellular_deinit(void);

/**
 * Start the PPP data connection.
 * Sends AT commands to configure PDP context and enters PPP mode.
 * Creates an esp_netif PPP interface that becomes available to lwIP.
 *
 * This is a blocking call that waits for IP assignment (up to 30s).
 *
 * @return ESP_OK if PPP connected and IP assigned
 */
esp_err_t ml_cellular_ppp_start(void);

/**
 * Stop the PPP data connection and return to AT command mode.
 */
esp_err_t ml_cellular_ppp_stop(void);

/**
 * Start cellular data using AT socket bridge (modem internal TCP/IP).
 * Uses AT+NETOPEN instead of PPP — bypasses CHAP authentication issues.
 * Initializes the AT socket bridge (ml_at_socket_init) which provides
 * BSD socket API wrappers over AT commands.
 *
 * @return ESP_OK if modem internal TCP/IP is active and has IP
 */
esp_err_t ml_cellular_data_start(void);

/**
 * Stop the AT socket bridge data connection.
 * Sends AT+NETCLOSE and deinitializes the AT socket bridge.
 */
esp_err_t ml_cellular_data_stop(void);

/**
 * Connect cellular data with automatic PPP→AT fallback.
 *
 * Attempts PPP connection first (30s timeout). If PPP fails (dial error,
 * CHAP auth failure, or IP assignment timeout), automatically falls back
 * to AT socket bridge (modem internal TCP/IP).
 *
 * PPP gives standard lwIP sockets (TCP+UDP, ~300ms latency).
 * AT socket bridge gives modem-managed TCP only (~3s latency).
 *
 * @return ESP_OK if connected via either PPP or AT
 */
esp_err_t ml_cellular_connect(void);

/**
 * Get the active data transport mode.
 * @return ML_DATA_MODE_PPP, ML_DATA_MODE_AT_SOCKET, or ML_DATA_MODE_NONE
 */
ml_cellular_data_mode_t ml_cellular_get_data_mode(void);

/**
 * Check if cellular is using AT socket bridge mode (not PPP).
 * When true, all MicroLink socket calls route through AT commands.
 */
bool ml_cellular_is_data_mode(void);

/**
 * Get current cellular state.
 */
ml_cellular_state_t ml_cellular_get_state(void);

/**
 * Get cellular module info (IMEI, signal, operator, etc).
 * @param info  Output structure (must not be NULL)
 * @return ESP_OK on success
 */
esp_err_t ml_cellular_get_info(ml_cellular_info_t *info);

/**
 * Get the IMEI string. Returns NULL if not available.
 * The returned pointer is valid until ml_cellular_deinit().
 */
const char *ml_cellular_get_imei(void);

/**
 * True when the SIM PIN guard has stopped sending the PIN: it was rejected
 * (or got no answer), too few attempts were left (AT+SPIC < 2), the SIM is
 * PUK-locked, or the modem cannot report the attempts left and the PIN was
 * already tried once this boot. ml_cellular_init() then fails with
 * ESP_ERR_NOT_ALLOWED (or ESP_ERR_INVALID_ARG for the rejection itself)
 * instead of risking a PUK lock. RAM only: cleared by a reboot or by
 * ml_cellular_reset_sim_pin_guard().
 */
bool ml_cellular_sim_pin_blocked(void);

/**
 * Clear the SIM PIN guard, e.g. after the application installed a corrected
 * PIN. The attempts-left check (AT+SPIC) still applies on the next init.
 */
void ml_cellular_reset_sim_pin_guard(void);

/** Upper bound for the timeout of an application AT command (the modem
 *  UART, and with it the AT socket bridge, is blocked for that long). */
#define ML_CELLULAR_AT_CMD_MAX_TIMEOUT_MS  30000

/**
 * Send one application AT command (e.g. a GPS query) and get the response.
 *
 * Thread-safe: takes the modem UART lock shared with the driver and the AT
 * socket bridge, so it can be used while the bridge carries the Tailscale
 * connection (CONFIG_ML_CELLULAR_DATA_AT_ONLY, or AUTO after PPP fell back).
 *
 * The command must be a single line starting with "AT", printable ASCII
 * only (no CR, LF, Ctrl-Z or ESC), at most ML_AT_CMD_MAX characters.
 * While the AT socket bridge is active, only "AT", "ATI" and allowlisted
 * query/information and GNSS commands (AT+CSQ, AT+CPSI?, AT+CREG?,
 * AT+CEREG?, AT+COPS?, AT+CCLK?, AT+CBC, AT+CPMUTEMP, AT+CGPS=1,
 * AT+CGPSINFO, AT+CGNSSINFO, ...) are accepted; anything else could break
 * the bridge or the UART link. See ml_at_cmd_allowed_with_bridge() in
 * ml_at_validate.h (the list is easy to extend).
 *
 * Not available while PPP owns the UART (state PPP_CONNECTING/CONNECTED):
 * returns -1. Use the modem's second UART/USB port for GNSS in PPP mode.
 *
 * Notes: the bridge is paused for the duration of the command, so keep
 * timeouts short. URCs that arrive in the response (e.g. "+IPCLOSE") are
 * still processed by the bridge. Unsolicited GNSS NMEA output on the main
 * UART is not supported.
 *
 * @param cmd        AT command string (without \r\n)
 * @param response   Buffer for the response (NUL-terminated, >= 2 bytes)
 * @param resp_size  Size of response buffer
 * @param timeout_ms Timeout in ms (<= 0: 5000; capped at
 *                   ML_CELLULAR_AT_CMD_MAX_TIMEOUT_MS)
 * @return Number of bytes received, or -1 if rejected, in the wrong state,
 *         or no response before the timeout
 */
int ml_cellular_send_at_cmd(const char *cmd, char *response, size_t resp_size, int timeout_ms);

/**
 * Same as ml_cellular_send_at_cmd() (kept for compatibility).
 */
int ml_cellular_send_at(const char *cmd, char *response, size_t resp_size, int timeout_ms);

/* ============================================================================
 * Internal: modem UART lock (used by ml_at_socket.c; never deleted once
 * created by ml_cellular_init()). Not for application use.
 * ========================================================================== */
bool ml_cellular_uart_lock(void);
void ml_cellular_uart_unlock(void);

#ifdef __cplusplus
}
#endif
