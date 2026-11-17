/**
 * @file ml_at_socket.c
 * @brief AT Socket Bridge — BSD socket API over SIM7600 internal TCP/IP stack
 *
 * Maps standard BSD socket calls to SIM7600 AT commands:
 *   socket()     → allocate link_num (0-9)
 *   connect()    → AT+CIPOPEN=N,"TCP",IP,port
 *   send()       → AT+CIPSEND=N,len then data
 *   recv()       → AT+CIPRXGET=2,N,len (active polling)
 *   sendto()     → AT+CIPSEND=N,len,"IP",port
 *   recvfrom()   → AT+CIPRXGET=2,N,len
 *   close()      → AT+CIPCLOSE=N
 *   getaddrinfo()→ AT+CDNSGIP="hostname"
 *   select()     → AT+CIPRXGET=4,N (query pending bytes)
 *
 * Architecture: Single-reader model. Only at_cmd() reads from UART.
 * No background URC handler task — URCs are processed inline when they
 * appear in AT command responses, and recv/select actively poll the modem.
 *
 * The UART is shared with ml_cellular.c (AT command mode, no PPP).
 * Locking (always in this order, never the reverse):
 *   1. The modem UART lock owned by ml_cellular.c (ml_cellular_uart_lock)
 *      serialises every AT exchange: socket commands, the driver itself and
 *      application commands (ml_cellular_send_at_cmd). It is never deleted.
 *   2. s_at.sock_lock protects each socket's RX ring and its buffer pointer,
 *      so a close() from one task cannot free a ring another task is reading.
 *
 * Known limitations (documented, not fixed here):
 *   - UDP datagram boundaries are not preserved (payloads share a byte ring).
 *     The source address is only known if the modem reports it in the
 *     +CIPRXGET header; otherwise recvfrom() reports 0.0.0.0:0.
 *   - Every AT exchange starts with uart_flush_input(), which can discard a
 *     URC (e.g. "+IPCLOSE") that arrived between commands. Data itself is
 *     not lost (manual RX mode keeps it in the modem until CIPRXGET=2).
 *   - Virtual FDs ML_AT_SOCK_FD_BASE..+ML_AT_SOCK_MAX-1 are routed here by
 *     number alone; see the static assertion below.
 */

#include "ml_at_socket.h"
#include "ml_at_validate.h"
#include "ml_cellular.h"
#include "microlink_internal.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>    /* sockaddr_in6, INET6_ADDRSTRLEN */

#ifdef CONFIG_ML_ENABLE_CELLULAR

static const char *TAG = "ml_at_sock";

/* AT socket FDs are recognised by number only (ml_at_socket_is_at_fd), so
 * they must not overlap lwIP's FD range [LWIP_SOCKET_OFFSET, FD_SETSIZE).
 * With FD_SETSIZE 64 this requires CONFIG_LWIP_MAX_SOCKETS <= 22. */
#if defined(LWIP_SOCKET_OFFSET)
_Static_assert(LWIP_SOCKET_OFFSET >= ML_AT_SOCK_FD_BASE + ML_AT_SOCK_MAX,
               "AT socket bridge FDs overlap lwIP FDs: reduce CONFIG_LWIP_MAX_SOCKETS to 22 or less");
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

#define AT_SOCK_MAX         ML_AT_SOCK_MAX  /* SIM7600 supports link_num 0-9 */
#define AT_SOCK_FD_BASE     ML_AT_SOCK_FD_BASE  /* Virtual FDs: 32-41 (within FD_SETSIZE=64) */
#define AT_MAX_SEND_CHUNK   1460    /* Max bytes per AT+CIPSEND */
#define AT_RESP_BUF_SIZE    512     /* AT response buffer */
#define AT_DATA_BUF_SIZE    4096    /* Data response buffer — room for 1460 data + headers */
#define UART_NUM            UART_NUM_1
#define AT_TIMEOUT_MS       5000
#define AT_LONG_TIMEOUT_MS  15000
#define DNS_TIMEOUT_MS      20000   /* DNS can be slow over cellular */
#define RX_RING_SIZE        8192    /* Per-socket RX ring buffer — 8KB for throughput */

/* ============================================================================
 * Internal Socket State
 * ========================================================================== */

typedef struct {
    int link_num;               /* SIM7600 socket ID (0-9), -1 = free */
    int type;                   /* SOCK_STREAM or SOCK_DGRAM */
    bool connected;
    bool bound;
    bool nonblocking;
    bool closed_by_remote;      /* Remote side closed the connection */
    bool rx_error;              /* RX stream desynchronised (bad length, short read) */
    uint32_t recv_timeout_ms;
    uint32_t send_timeout_ms;
    uint16_t local_port;        /* For UDP bind */

    /* RX ring buffer — filled by active polling via AT+CIPRXGET=2 */
    uint8_t *rx_buf;
    volatile size_t rx_head;    /* Write position */
    volatile size_t rx_tail;    /* Read position */
    size_t rx_size;             /* Ring buffer capacity */

    /* Last UDP source (from the +CIPRXGET header, if the modem reports it) */
    uint32_t last_src_ip;
    uint16_t last_src_port;

    /* Async connect result — set by process_urcs() */
    volatile bool connect_done;
    volatile bool connect_ok;
} ml_at_sock_t;

static struct {
    volatile bool initialized;
    bool net_open;
    ml_at_sock_t socks[AT_SOCK_MAX];
    SemaphoreHandle_t sock_lock;    /* RX rings + rx_buf pointers; never deleted */
} s_at = {0};

/* Modem UART lock (shared with ml_cellular.c). It is created by
 * ml_cellular_init() before the bridge can start and never deleted. */
#define AT_LOCK()    ((void)ml_cellular_uart_lock())
#define AT_UNLOCK()  ml_cellular_uart_unlock()

/* ============================================================================
 * Ring Buffer Helpers
 * ========================================================================== */

static inline size_t ring_used(const ml_at_sock_t *s) {
    if (s->rx_size == 0) return 0;
    return (s->rx_head + s->rx_size - s->rx_tail) % s->rx_size;
}

static inline size_t ring_free(const ml_at_sock_t *s) {
    return s->rx_size - 1 - ring_used(s);
}

static size_t ring_write(ml_at_sock_t *s, const uint8_t *data, size_t len) {
    size_t written = 0;
    while (written < len && ring_free(s) > 0) {
        s->rx_buf[s->rx_head] = data[written++];
        s->rx_head = (s->rx_head + 1) % s->rx_size;
    }
    return written;
}

static size_t ring_read(ml_at_sock_t *s, uint8_t *data, size_t len) {
    size_t read_count = 0;
    while (read_count < len && ring_used(s) > 0) {
        data[read_count++] = s->rx_buf[s->rx_tail];
        s->rx_tail = (s->rx_tail + 1) % s->rx_size;
    }
    return read_count;
}

/* Locked ring access. A socket can be closed (and its ring freed) by another
 * task; these re-check the slot under sock_lock before touching rx_buf. */

/* Copy buffered RX bytes out. Returns bytes copied (0 if none), or -1 if the
 * socket was closed concurrently. */
static int sock_ring_take(ml_at_sock_t *s, uint8_t *buf, size_t len)
{
    int n = -1;
    xSemaphoreTake(s_at.sock_lock, portMAX_DELAY);
    if (s->link_num >= 0 && s->rx_buf) {
        n = (int)ring_read(s, buf, len);
    }
    xSemaphoreGive(s_at.sock_lock);
    return n;
}

/* Append received bytes. Returns bytes stored (less than len only if the
 * socket was closed or the ring is full). */
static size_t sock_ring_put(ml_at_sock_t *s, const uint8_t *data, size_t len)
{
    size_t n = 0;
    xSemaphoreTake(s_at.sock_lock, portMAX_DELAY);
    if (s->link_num >= 0 && s->rx_buf) {
        n = ring_write(s, data, len);
    }
    xSemaphoreGive(s_at.sock_lock);
    return n;
}

/* Something for recv() to report: data, EOF or an error */
static bool sock_rx_ready(ml_at_sock_t *s)
{
    bool ready;
    xSemaphoreTake(s_at.sock_lock, portMAX_DELAY);
    ready = s->link_num >= 0 &&
            (ring_used(s) > 0 || s->closed_by_remote || s->rx_error);
    xSemaphoreGive(s_at.sock_lock);
    return ready;
}

/* ============================================================================
 * URC Processing (inline — called from at_cmd response parsing)
 *
 * When at_cmd() reads a response, it may contain interleaved URCs.
 * This function scans the response buffer for URC lines and dispatches them.
 * ========================================================================== */

static void process_urc_line(const char *line)
{
    /* +IPCLOSE: <link_num>,<reason> — remote closed */
    if (strncmp(line, "+IPCLOSE:", 9) == 0) {
        int link_num = atoi(line + 9);
        if (link_num >= 0 && link_num < AT_SOCK_MAX) {
            ESP_LOGI(TAG, "URC: remote closed link %d", link_num);
            s_at.socks[link_num].closed_by_remote = true;
        }
        return;
    }

    /* +CIPOPEN: <link_num>,<err> — async connect result */
    if (strncmp(line, "+CIPOPEN:", 9) == 0) {
        int link_num, err;
        if (sscanf(line + 9, " %d,%d", &link_num, &err) == 2) {
            if (link_num >= 0 && link_num < AT_SOCK_MAX) {
                s_at.socks[link_num].connect_done = true;
                s_at.socks[link_num].connect_ok = (err == 0);
                if (err == 0) {
                    s_at.socks[link_num].connected = true;
                    ESP_LOGI(TAG, "URC: link %d connected", link_num);
                } else {
                    ESP_LOGW(TAG, "URC: link %d connect failed err=%d", link_num, err);
                }
            }
        }
        return;
    }

    /* +CIPRXGET: 1,<link_num> — data notification (we ignore; we poll actively) */
    if (strncmp(line, "+CIPRXGET: 1,", 13) == 0) {
        int link_num = atoi(line + 13);
        ESP_LOGD(TAG, "URC: data notification on link %d (ignored, will poll)", link_num);
        return;
    }
}

/* Scan response buffer for URC lines and process them.
 * This is called after at_cmd() finishes reading a response.
 * URCs can be interleaved with the expected response. */
static void process_urcs_in_response(const char *resp)
{
    const char *p = resp;
    while (p && *p) {
        /* Skip whitespace/newlines */
        while (*p == '\r' || *p == '\n' || *p == ' ') p++;
        if (!*p) break;

        /* Find end of line */
        const char *eol = strchr(p, '\n');
        if (!eol) eol = p + strlen(p);

        /* Extract line (without trailing \r\n) */
        int line_len = (int)(eol - p);
        if (line_len > 0 && p[line_len - 1] == '\r') line_len--;

        if (line_len > 0 && line_len < 256) {
            char line[256];
            memcpy(line, p, line_len);
            line[line_len] = '\0';

            /* Check if it's a URC */
            if (line[0] == '+') {
                process_urc_line(line);
            }
        }

        p = (*eol) ? eol + 1 : eol;
    }
}

/* ============================================================================
 * AT Command Helpers (single-reader model — sole UART reader)
 * ========================================================================== */

/* Binary-safe search: find needle in haystack of given length.
 * Like memmem() but portable. */
static void *bin_search(const void *haystack, size_t haystack_len,
                         const char *needle, size_t needle_len)
{
    if (needle_len > haystack_len) return NULL;
    const uint8_t *h = (const uint8_t *)haystack;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(h + i, needle, needle_len) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

/* Send an AT command and wait for response.
 * Caller must hold the UART lock.
 * Processes any URCs found in the response.
 * Uses binary-safe search (memmem) so null bytes in data don't hang. */
/* Write "<cmd>\r\n". Refuses (rather than truncates) an over-long command,
 * since truncation would drop the CR and merge it with the next command. */
static bool at_write_cmd(const char *cmd)
{
    char cmd_buf[512];
    size_t len = strlen(cmd);
    if (len > sizeof(cmd_buf) - 3) {
        ESP_LOGE(TAG, "AT command too long (%u bytes)", (unsigned)len);
        return false;
    }
    memcpy(cmd_buf, cmd, len);
    cmd_buf[len] = '\r';
    cmd_buf[len + 1] = '\n';
    uart_write_bytes(UART_NUM, cmd_buf, len + 2);
    ml_at_secure_zero(cmd_buf, sizeof(cmd_buf));
    return true;
}

static int at_cmd(const char *cmd, char *resp, size_t resp_size, int timeout_ms)
{
    char log_cmd[48];
    memset(resp, 0, resp_size);
    if (resp_size < 2) return 0;

    uart_flush_input(UART_NUM);
    if (!at_write_cmd(cmd)) return 0;

    ESP_LOGD(TAG, ">> %s", ml_at_redact_cmd(cmd, log_cmd, sizeof(log_cmd)));

    int total = 0;
    int64_t start = esp_timer_get_time();
    int64_t timeout_us = (int64_t)timeout_ms * 1000;

    while ((esp_timer_get_time() - start) < timeout_us) {
        if ((size_t)total >= resp_size - 1) {
            /* Full without a final result code: stop rather than spin on
             * zero-length reads while holding the UART lock. */
            ESP_LOGW(TAG, "AT response truncated at %d bytes", total);
            break;
        }
        /* Short UART read timeout (20ms) for fast AT round-trips.
         * At 921600 baud, 1460 bytes take ~16ms to transfer. */
        int len = uart_read_bytes(UART_NUM,
                                   (uint8_t *)(resp + total),
                                   resp_size - total - 1,
                                   pdMS_TO_TICKS(20));
        if (len > 0) {
            total += len;
            resp[total] = '\0';
            /* Binary-safe: scan full buffer including past null bytes */
            if (bin_search(resp, total, "\r\nOK\r\n", 6) ||
                bin_search(resp, total, "\nOK\r\n", 5) ||
                bin_search(resp, total, "\r\nERROR\r\n", 9) ||
                bin_search(resp, total, "\r\n+CME ERROR", 12) ||
                bin_search(resp, total, "\r\n+CMS ERROR", 12)) {
                break;
            }
            /* Also check if buffer starts with OK (no preceding \r\n) */
            if (total >= 4 && memcmp(resp, "OK\r\n", 4) == 0) {
                break;
            }
        }
    }

    if (total > 0) {
        ESP_LOGD(TAG, "<< [%d bytes]", total);
        /* Process any URCs that appeared in the response */
        process_urcs_in_response(resp);
    }
    return total;
}

static bool at_cmd_ok(const char *cmd, int timeout_ms)
{
    char resp[AT_RESP_BUF_SIZE];
    int len = at_cmd(cmd, resp, sizeof(resp), timeout_ms);
    return (len > 0 && strstr(resp, "OK") != NULL);
}

/* Send an AT command and wait for a specific URC pattern (e.g. +CDNSGIP).
 * After getting OK, continues reading for the async URC response.
 * Caller must hold the UART lock. */
static int at_cmd_wait_urc(const char *cmd, const char *urc_prefix,
                            char *resp, size_t resp_size, int timeout_ms)
{
    char log_cmd[48];
    memset(resp, 0, resp_size);
    if (resp_size < 2) return 0;

    uart_flush_input(UART_NUM);
    if (!at_write_cmd(cmd)) return 0;

    ESP_LOGD(TAG, ">> %s (wait for %s)", ml_at_redact_cmd(cmd, log_cmd, sizeof(log_cmd)),
             urc_prefix);

    int total = 0;
    int64_t start = esp_timer_get_time();
    int64_t timeout_us = (int64_t)timeout_ms * 1000;
    bool got_ok = false;
    bool got_urc = false;

    while ((esp_timer_get_time() - start) < timeout_us) {
        if ((size_t)total >= resp_size - 1) {
            ESP_LOGW(TAG, "AT response full (%d bytes) before %s", total, urc_prefix);
            break;
        }
        int len = uart_read_bytes(UART_NUM,
                                   (uint8_t *)(resp + total),
                                   resp_size - total - 1,
                                   pdMS_TO_TICKS(100));
        if (len > 0) {
            total += len;
            resp[total] = '\0';

            if (!got_ok && (strstr(resp, "OK") || strstr(resp, "ERROR"))) {
                got_ok = true;
                /* If ERROR, stop immediately */
                if (strstr(resp, "ERROR")) break;
            }

            /* Check if the URC we're waiting for has arrived */
            if (strstr(resp, urc_prefix)) {
                got_urc = true;
                /* Give a tiny bit more time for trailing data */
                vTaskDelay(pdMS_TO_TICKS(100));
                if ((size_t)total >= resp_size - 1) break;
                len = uart_read_bytes(UART_NUM,
                                       (uint8_t *)(resp + total),
                                       resp_size - total - 1,
                                       pdMS_TO_TICKS(200));
                if (len > 0) {
                    total += len;
                    resp[total] = '\0';
                }
                break;
            }
        }
    }

    if (total > 0) {
        ESP_LOGD(TAG, "<< [%d bytes] %s", total, resp);
        process_urcs_in_response(resp);
    }

    if (!got_urc) {
        ESP_LOGW(TAG, "Timed out waiting for %s", urc_prefix);
    }
    return total;
}

/* Send raw data (after AT+CIPSEND prompt).
 * Caller must hold the UART lock. */
static int at_send_raw(const void *data, size_t len, int timeout_ms)
{
    uart_write_bytes(UART_NUM, data, len);

    /* Wait for response (OK or ERROR) */
    char resp[256];
    int total = 0;
    int64_t start = esp_timer_get_time();
    int64_t timeout_us = (int64_t)timeout_ms * 1000;
    memset(resp, 0, sizeof(resp));

    while ((esp_timer_get_time() - start) < timeout_us) {
        if (total >= (int)sizeof(resp) - 1) break;   /* full: no zero-length spin */
        int n = uart_read_bytes(UART_NUM,
                                 (uint8_t *)(resp + total),
                                 sizeof(resp) - total - 1,
                                 pdMS_TO_TICKS(100));
        if (n > 0) {
            total += n;
            resp[total] = '\0';
            if (strstr(resp, "OK") || strstr(resp, "ERROR")) {
                break;
            }
        }
    }

    return (strstr(resp, "OK") != NULL) ? (int)len : -1;
}

/* Format IP from sockaddr to string (supports both IPv4 and IPv6) */
/* Returns false (buf left empty) for a NULL, short or non-IP address, so an
 * uninitialised string is never put into an AT command. */
static bool sockaddr_to_str(const struct sockaddr *addr, socklen_t addrlen,
                            char *buf, size_t buflen, uint16_t *port)
{
    buf[0] = '\0';
    if (!addr) return false;
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        if (!inet_ntoa_r(sin->sin_addr, buf, buflen)) return false;
        if (port) *port = ntohs(sin->sin_port);
        return true;
    }
    if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        if (!inet_ntop(AF_INET6, &sin6->sin6_addr, buf, buflen)) return false;
        if (port) *port = ntohs(sin6->sin6_port);
        return true;
    }
    return false;
}

/* ============================================================================
 * Active Polling for RX Data
 *
 * Instead of relying on a URC handler task, we actively poll the modem
 * for pending data using AT+CIPRXGET commands.
 * ========================================================================== */

/* Query how many bytes are pending for a given link.
 * Uses AT+CIPRXGET=4,N → +CIPRXGET: 4,<link_num>,<pending_len>
 * Caller must hold the UART lock. */
static int at_query_pending(int link_num)
{
    char cmd[32];
    char resp[AT_RESP_BUF_SIZE];

    int64_t t0 = esp_timer_get_time();
    snprintf(cmd, sizeof(cmd), "AT+CIPRXGET=4,%d", link_num);
    int len = at_cmd(cmd, resp, sizeof(resp), AT_TIMEOUT_MS);
    if (len <= 0) return 0;

    /* Parse +CIPRXGET: 4,<link_num>,<pending_len> */
    char *p = strstr(resp, "+CIPRXGET: 4,");
    if (!p) return 0;

    int ln, pending;
    if (sscanf(p, "+CIPRXGET: 4,%d,%d", &ln, &pending) >= 2) {
        int64_t elapsed_ms = (esp_timer_get_time() - t0) / 1000;
        if (pending > 0) {
            ESP_LOGD(TAG, "QUERY: link=%d pending=%d %ldms", link_num, pending, (long)elapsed_ms);
        }
        return pending;
    }
    return 0;
}

/* Read one chunk of data from modem into socket's ring buffer.
 * Binary-safe: reads response in phases:
 *   1. Text header: +CIPRXGET: 2,<link>,<actual>,<remaining>\r\n
 *   2. Binary data: exactly <actual> bytes
 *   3. Trailing: \r\nOK\r\n
 * The modem-reported lengths are validated (link must match, actual must be
 * <= what we asked for and fit in the ring). A bad header, a short read or a
 * ring overflow means the byte stream is out of sync: the socket is marked
 * rx_error (recv() then fails with EIO once buffered data is consumed)
 * instead of silently dropping bytes inside a TLS stream.
 * Caller must hold the UART lock.
 * Returns: bytes written to ring (0 = no data), or -1 on error. */
static int at_read_data_chunk(int link_num, int max_bytes, int *out_remaining)
{
    if (out_remaining) *out_remaining = 0;
    if (link_num < 0 || link_num >= AT_SOCK_MAX) return 0;
    ml_at_sock_t *s = &s_at.socks[link_num];
    if (s->link_num < 0 || !s->rx_buf || s->rx_error) return 0;

    /* Only readers run concurrently, and they only free space, so this is
     * a lower bound for the whole read. close() needs the UART lock. */
    int req_len = max_bytes;
    size_t free_space = ring_free(s);
    if ((size_t)req_len > free_space) req_len = (int)free_space;
    if (req_len <= 0) return 0;
    if (req_len > AT_MAX_SEND_CHUNK) req_len = AT_MAX_SEND_CHUNK;

    /* Send command */
    uart_flush_input(UART_NUM);
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "AT+CIPRXGET=2,%d,%d\r\n", link_num, req_len);
    uart_write_bytes(UART_NUM, cmd, strlen(cmd));

    /* Phase 1: Read text header line.
     * Looking for: +CIPRXGET: 2,<link>,<actual>,<remaining>\r\n
     * The header is pure ASCII text, so strstr is safe here. */
    char hdr[128];
    int hdr_total = 0;
    int64_t start = esp_timer_get_time();
    int64_t timeout_us = (int64_t)AT_TIMEOUT_MS * 1000;
    ml_at_rxget_hdr_t h;
    int data_off = 0;
    bool got_header = false;

    while ((esp_timer_get_time() - start) < timeout_us) {
        if (hdr_total >= (int)sizeof(hdr) - 1) {
            /* Full of URC lines that arrived before the header: handle the
             * complete lines and keep only the trailing partial line, instead
             * of spinning on zero-length reads until the timeout. */
            int keep_from = hdr_total - 16;   /* no line break: keep a tail */
            for (int i = hdr_total - 1; i >= 0; i--) {
                if (hdr[i] == '\n') {
                    hdr[i] = '\0';
                    process_urcs_in_response(hdr);
                    keep_from = i + 1;
                    break;
                }
            }
            memmove(hdr, hdr + keep_from, hdr_total - keep_from);
            hdr_total -= keep_from;
            hdr[hdr_total] = '\0';
        }

        int n = uart_read_bytes(UART_NUM,
                                 (uint8_t *)(hdr + hdr_total),
                                 sizeof(hdr) - hdr_total - 1,
                                 pdMS_TO_TICKS(20));
        if (n <= 0) continue;
        hdr_total += n;
        hdr[hdr_total] = '\0';

        char *p = strstr(hdr, "+CIPRXGET: 2,");
        if (p) {
            char *nl = memchr(p, '\n', (size_t)(hdr_total - (p - hdr)));
            if (!nl) continue;   /* header line not complete yet */
            if (!ml_at_parse_rxget_hdr(p, (size_t)(nl - p), AT_SOCK_MAX, req_len, &h) ||
                h.link != link_num) {
                ESP_LOGE(TAG, "link %d: bad +CIPRXGET header (requested %d): %.*s",
                         link_num, req_len, (int)(nl - p), p);
                goto desync;
            }
            data_off = (int)(nl + 1 - hdr);
            got_header = true;
            break;
        }

        /* No header: an ERROR here means no data / link not open */
        if (strstr(hdr, "ERROR")) {
            return 0;
        }
    }

    if (!got_header) {
        return 0;
    }

    int actual_len = h.read_len;
    int total_written = 0;

    /* Data bytes that arrived in the same read as the header */
    int piggy = hdr_total - data_off;
    if (piggy > 0 && actual_len > 0) {
        int take = (piggy > actual_len) ? actual_len : piggy;
        if (sock_ring_put(s, (const uint8_t *)(hdr + data_off), take) != (size_t)take) {
            goto overflow;
        }
        total_written += take;
        actual_len -= take;
    }

    /* Phase 2: Read remaining binary data bytes directly into ring buffer.
     * We know exactly how many bytes to expect — no string parsing needed.
     * Use a large buffer to minimize uart_read_bytes() calls (each call has
     * timeout overhead even when data is available). */
    uint8_t chunk[AT_MAX_SEND_CHUNK];
    while (actual_len > 0 && (esp_timer_get_time() - start) < timeout_us) {
        int want = (actual_len > (int)sizeof(chunk)) ? (int)sizeof(chunk) : actual_len;
        int n = uart_read_bytes(UART_NUM, chunk, want, pdMS_TO_TICKS(20));
        if (n > 0) {
            if (sock_ring_put(s, chunk, n) != (size_t)n) {
                goto overflow;
            }
            total_written += n;
            actual_len -= n;
        }
    }
    if (actual_len > 0) {
        ESP_LOGE(TAG, "link %d: timed out with %d of %d bytes missing",
                 link_num, actual_len, h.read_len);
        goto desync;
    }

    if (h.has_src) {
        s->last_src_ip = h.src_ip;
        s->last_src_port = h.src_port;
    }

    /* Phase 3: Consume trailing \r\nOK\r\n (don't care about exact content).
     * Short timeout — data is already flowing, just need to clear the tail. */
    uint8_t trail[32];
    uart_read_bytes(UART_NUM, trail, sizeof(trail), pdMS_TO_TICKS(5));

    if (out_remaining) *out_remaining = h.rest_len;

    int64_t chunk_elapsed_ms = (esp_timer_get_time() - start) / 1000;
    ESP_LOGD(TAG, "CHUNK: link=%d req=%d got=%d remaining=%d %ldms",
             link_num, req_len, total_written, h.rest_len, (long)chunk_elapsed_ms);

    return total_written;

overflow:
    ESP_LOGE(TAG, "link %d: RX ring overflow (socket closed or ring full)", link_num);
desync:
    s->rx_error = true;
    uart_flush_input(UART_NUM);
    return -1;
}

/* Read ALL available data from modem into socket's ring buffer.
 * Keeps reading in a loop while remaining > 0.
 * Caller must hold the UART lock.
 * Returns total bytes read. Sets *out_remaining to bytes still in modem. */
static int at_read_data(int link_num, int max_bytes, int *out_remaining)
{
    int total = 0;
    int remaining = 0;

    /* Read first chunk */
    int got = at_read_data_chunk(link_num, max_bytes, &remaining);
    if (got > 0) total += got;

    /* Keep reading while there's more data and ring buffer has space */
    while (remaining > 0 && got > 0 && ring_free(&s_at.socks[link_num]) > 0) {
        got = at_read_data_chunk(link_num, remaining, &remaining);
        if (got > 0) total += got;
    }

    if (out_remaining) *out_remaining = remaining;
    return total;
}

/* ============================================================================
 * Initialization
 * ========================================================================== */

esp_err_t ml_at_socket_init(void)
{
    if (s_at.initialized) {
        ESP_LOGW(TAG, "Already initialized");
        return ESP_ERR_INVALID_STATE;
    }

    /* Initialize socket array */
    for (int i = 0; i < AT_SOCK_MAX; i++) {
        s_at.socks[i].link_num = -1; /* Free */
    }

    /* Ring lock: created once, never deleted (tasks may still hold a
     * socket pointer after deinit; they re-check the slot under it). */
    if (!s_at.sock_lock) {
        s_at.sock_lock = xSemaphoreCreateMutex();
        if (!s_at.sock_lock) {
            ESP_LOGE(TAG, "Failed to create socket lock");
            return ESP_ERR_NO_MEM;
        }
    }

    /* Close any existing network session */
    if (!ml_cellular_uart_lock()) {
        ESP_LOGE(TAG, "Modem UART not initialized (call ml_cellular_init first)");
        return ESP_ERR_INVALID_STATE;
    }
    at_cmd_ok("AT+NETCLOSE", AT_TIMEOUT_MS);
    vTaskDelay(pdMS_TO_TICKS(1000));

    /* Set manual RX mode (we poll with AT+CIPRXGET=2) */
    at_cmd_ok("AT+CIPRXGET=1", AT_TIMEOUT_MS);

    /* Open network */
    char resp[AT_RESP_BUF_SIZE];
    at_cmd("AT+NETOPEN", resp, sizeof(resp), AT_LONG_TIMEOUT_MS);
    AT_UNLOCK();

    if (!strstr(resp, "OK") && !strstr(resp, "+NETOPEN: 0") && !strstr(resp, "already opened")) {
        ESP_LOGE(TAG, "AT+NETOPEN failed: %s", resp);
        return ESP_FAIL;
    }

    /* Wait for network to be ready */
    vTaskDelay(pdMS_TO_TICKS(2000));

    /* Verify IP address */
    AT_LOCK();
    at_cmd("AT+IPADDR", resp, sizeof(resp), AT_TIMEOUT_MS);
    AT_UNLOCK();

    char *ip_start = strstr(resp, "+IPADDR:");
    if (ip_start) {
        ESP_LOGI(TAG, "Modem IP: %s", ip_start);
    } else {
        ESP_LOGW(TAG, "Could not get modem IP address");
    }

    s_at.net_open = true;
    s_at.initialized = true;
    ESP_LOGI(TAG, "AT socket bridge initialized (single-reader mode)");
    return ESP_OK;
}

void ml_at_socket_deinit(void)
{
    if (!s_at.initialized) return;

    /* Close all sockets */
    for (int i = 0; i < AT_SOCK_MAX; i++) {
        if (s_at.socks[i].link_num >= 0) {
            ml_at_close(AT_SOCK_FD_BASE + i);
        }
    }

    /* Close network */
    if (s_at.net_open) {
        AT_LOCK();
        at_cmd_ok("AT+NETCLOSE", AT_TIMEOUT_MS);
        AT_UNLOCK();
        s_at.net_open = false;
    }

    /* The UART lock and sock_lock are intentionally not deleted: another
     * task may be blocked on them, and deleting a semaphore with waiters is
     * undefined. Such a task finds its socket closed (EBADF). */
    s_at.initialized = false;
    ESP_LOGI(TAG, "AT socket bridge deinitialized");
}

bool ml_at_socket_is_ready(void)
{
    return s_at.initialized && s_at.net_open;
}

int ml_at_socket_cmd_locked(const char *cmd, char *resp, size_t resp_size, int timeout_ms)
{
    if (!s_at.initialized || !cmd || !resp || resp_size < 2) return -1;
    int n = at_cmd(cmd, resp, resp_size, timeout_ms);
    return (n > 0) ? n : -1;
}

/* ============================================================================
 * Socket API
 * ========================================================================== */

bool ml_at_socket_is_at_fd(int fd)
{
    return fd >= AT_SOCK_FD_BASE && fd < AT_SOCK_FD_BASE + AT_SOCK_MAX;
}

static ml_at_sock_t *fd_to_sock(int fd)
{
    if (!s_at.initialized || !ml_at_socket_is_at_fd(fd)) return NULL;
    int idx = fd - AT_SOCK_FD_BASE;
    ml_at_sock_t *s = &s_at.socks[idx];
    return (s->link_num >= 0) ? s : NULL;
}

int ml_at_socket(int domain, int type, int protocol)
{
    if (!s_at.initialized) {
        errno = ENETDOWN;
        return -1;
    }

    /* Accept AF_INET and AF_INET6 — the modem handles IPv6 transparently
     * via AT+CIPOPEN with IPv6 address strings. The domain is stored but
     * the AT bridge doesn't differentiate at the link level. */
    if (domain != AF_INET && domain != AF_INET6) {
        ESP_LOGW(TAG, "Unsupported domain %d (need AF_INET or AF_INET6)", domain);
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
        errno = EPROTOTYPE;
        return -1;
    }

    /* Allocate RX ring buffer (ml_psram_malloc falls back to internal RAM) */
    uint8_t *rx_buf = ml_psram_malloc(RX_RING_SIZE);
    if (!rx_buf) {
        errno = ENOMEM;
        return -1;
    }

    /* Claim a free slot. Every field is set before link_num publishes the
     * slot, so a concurrent select()/recv() never sees rx_size == 0. */
    xSemaphoreTake(s_at.sock_lock, portMAX_DELAY);
    for (int i = 0; i < AT_SOCK_MAX; i++) {
        if (s_at.socks[i].link_num < 0) {
            ml_at_sock_t *s = &s_at.socks[i];
            memset(s, 0, sizeof(*s));
            s->link_num = -1;
            s->type = type;
            s->recv_timeout_ms = 10000; /* Default 10s */
            s->send_timeout_ms = 10000;
            s->rx_size = RX_RING_SIZE;
            s->rx_buf = rx_buf;
            s->link_num = i;
            xSemaphoreGive(s_at.sock_lock);

            int fd = AT_SOCK_FD_BASE + i;
            ESP_LOGI(TAG, "socket(%s) -> fd=%d link=%d",
                     type == SOCK_STREAM ? "TCP" : "UDP", fd, i);
            return fd;
        }
    }
    xSemaphoreGive(s_at.sock_lock);
    free(rx_buf);

    ESP_LOGE(TAG, "No free AT sockets (max %d)", AT_SOCK_MAX);
    errno = EMFILE;
    return -1;
}

int ml_at_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }

    char ip_str[INET6_ADDRSTRLEN];  /* 46 bytes — fits IPv4 and IPv6 */
    uint16_t port = 0;
    if (!sockaddr_to_str(addr, addrlen, ip_str, sizeof(ip_str), &port)) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    const char *proto = (s->type == SOCK_STREAM) ? "TCP" : "UDP";
    char cmd[192];  /* Larger for IPv6 addresses */

    if (s->type == SOCK_DGRAM && s->local_port > 0) {
        /* UDP with local port binding */
        snprintf(cmd, sizeof(cmd), "AT+CIPOPEN=%d,\"%s\",\"%s\",%u,%u",
                 s->link_num, proto, ip_str, port, s->local_port);
    } else {
        snprintf(cmd, sizeof(cmd), "AT+CIPOPEN=%d,\"%s\",\"%s\",%u",
                 s->link_num, proto, ip_str, port);
    }

    ESP_LOGI(TAG, "connect: %s", cmd);

    s->connect_done = false;
    s->connect_ok = false;

    /* For TCP, we need to wait for the async +CIPOPEN: N,0 URC for THIS
     * link (a late result for another link must not count). */
    char urc[24];
    snprintf(urc, sizeof(urc), "+CIPOPEN: %d,", s->link_num);
    char resp[AT_RESP_BUF_SIZE];
    AT_LOCK();
    if (s->link_num < 0) {          /* closed by another task meanwhile */
        AT_UNLOCK();
        errno = EBADF;
        return -1;
    }

    if (s->type == SOCK_STREAM) {
        /* TCP: wait for +CIPOPEN URC */
        at_cmd_wait_urc(cmd, urc, resp, sizeof(resp), AT_LONG_TIMEOUT_MS);
    } else {
        /* UDP: just need OK */
        at_cmd(cmd, resp, sizeof(resp), AT_LONG_TIMEOUT_MS);
    }
    AT_UNLOCK();

    /* Check for inline connect result: exactly "+CIPOPEN: <link>,0" */
    const char *res = strstr(resp, urc);
    int open_err = -1;
    if (res && sscanf(res + strlen(urc), "%d", &open_err) == 1 && open_err == 0) {
        s->connected = true;
        ESP_LOGI(TAG, "connect: link %d connected", s->link_num);
        return 0;
    }

    /* Check async result (processed by process_urcs_in_response) */
    if (s->connect_done && s->connect_ok) {
        ESP_LOGI(TAG, "connect: link %d connected (URC)", s->link_num);
        return 0;
    }

    if (s->type == SOCK_DGRAM) {
        /* UDP "connect" just stores the remote for sendto default */
        if (strstr(resp, "OK")) {
            s->connected = true;
            return 0;
        }
    }

    ESP_LOGW(TAG, "connect: link %d failed: %s", s->link_num, resp);
    errno = ECONNREFUSED;
    return -1;
}

ssize_t ml_at_send(int fd, const void *buf, size_t len, int flags)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }
    if (!s->connected) { errno = ENOTCONN; return -1; }

    const uint8_t *data = (const uint8_t *)buf;
    size_t total_sent = 0;

    while (total_sent < len) {
        size_t chunk = len - total_sent;
        if (chunk > AT_MAX_SEND_CHUNK) chunk = AT_MAX_SEND_CHUNK;

        char cmd[64];
        snprintf(cmd, sizeof(cmd), "AT+CIPSEND=%d,%d", s->link_num, (int)chunk);

        AT_LOCK();
        if (s->link_num < 0) {      /* closed by another task meanwhile */
            AT_UNLOCK();
            if (total_sent > 0) return total_sent;
            errno = EBADF;
            return -1;
        }

        /* Send the command and wait for '>' prompt */
        char resp[256];
        uart_flush_input(UART_NUM);
        char cmd_buf[128];
        snprintf(cmd_buf, sizeof(cmd_buf), "%s\r\n", cmd);
        uart_write_bytes(UART_NUM, cmd_buf, strlen(cmd_buf));

        /* Wait for '>' prompt */
        int resp_len = 0;
        int64_t start = esp_timer_get_time();
        memset(resp, 0, sizeof(resp));
        bool got_prompt = false;
        while ((esp_timer_get_time() - start) < (int64_t)AT_TIMEOUT_MS * 1000) {
            if (resp_len >= (int)sizeof(resp) - 1) break;   /* full: no zero-length spin */
            int n = uart_read_bytes(UART_NUM,
                                     (uint8_t *)(resp + resp_len),
                                     sizeof(resp) - resp_len - 1,
                                     pdMS_TO_TICKS(50));
            if (n > 0) {
                resp_len += n;
                resp[resp_len] = '\0';
                if (strchr(resp, '>')) {
                    got_prompt = true;
                    break;
                }
                if (strstr(resp, "ERROR")) break;
            }
        }

        if (!got_prompt) {
            AT_UNLOCK();
            ESP_LOGW(TAG, "send: no '>' prompt for link %d", s->link_num);
            if (total_sent > 0) return total_sent;
            errno = EIO;
            return -1;
        }

        /* Send the raw data */
        int sent = at_send_raw(data + total_sent, chunk, s->send_timeout_ms);
        AT_UNLOCK();

        if (sent < 0) {
            ESP_LOGW(TAG, "send: data send failed for link %d", s->link_num);
            if (total_sent > 0) return total_sent;
            errno = EIO;
            return -1;
        }

        total_sent += chunk;
    }

    return total_sent;
}

/* Ask the modem for pending bytes on link idx and drain them into the ring.
 * Returns false if the socket was closed meanwhile. */
static bool poll_link(ml_at_sock_t *s, int idx, int *drained, int *remaining)
{
    int got = 0, rem = 0;
    AT_LOCK();
    if (s->link_num != idx) {
        AT_UNLOCK();
        return false;
    }
    int pending = at_query_pending(idx);
    if (pending > 0) {
        /* at_read_data drains ALL pending data in a loop internally */
        got = at_read_data(idx, pending, &rem);
    }
    AT_UNLOCK();
    if (drained) *drained = got;
    if (remaining) *remaining = rem;
    return true;
}

/* Deliver buffered data, EOF or a pending error. Returns 1 if *ret is set. */
static int recv_ready_result(ml_at_sock_t *s, void *buf, size_t len, ssize_t *ret)
{
    int n = sock_ring_take(s, (uint8_t *)buf, len);
    if (n > 0) { *ret = n; return 1; }
    if (n < 0) { errno = EBADF; *ret = -1; return 1; }
    if (s->rx_error) { errno = EIO; *ret = -1; return 1; }
    if (s->closed_by_remote) { *ret = 0; return 1; }   /* EOF */
    return 0;
}

ssize_t ml_at_recv(int fd, void *buf, size_t len, int flags)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }
    int idx = fd - AT_SOCK_FD_BASE;
    ssize_t ret;

    if (len == 0) return 0;

    /* Check ring buffer first — fast path, no AT commands */
    if (recv_ready_result(s, buf, len, &ret)) return ret;

    /* Non-blocking mode */
    if (s->nonblocking) {
        if (!poll_link(s, idx, NULL, NULL)) { errno = EBADF; return -1; }
        if (recv_ready_result(s, buf, len, &ret)) return ret;
        errno = EAGAIN;
        return -1;
    }

    /* Blocking mode with drain optimization:
     * - Query modem immediately (no initial sleep)
     * - When data found: drain ALL pending data before returning
     * - When no data: backoff with short intervals
     * - Return as soon as we have ANY data in the ring buffer */
    int64_t start = esp_timer_get_time();
    int64_t timeout_us = (int64_t)s->recv_timeout_ms * 1000;
    bool first_poll = true;  /* No delay before first poll */

    do {
        if (!first_poll) {
            /* Short fixed delay between polls — 10ms balances throughput
             * with CPU usage. Lower than 10ms starves other tasks. */
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        first_poll = false;

        int total_drained = 0, remaining = 0;
        if (!poll_link(s, idx, &total_drained, &remaining)) {
            errno = EBADF;
            return -1;
        }

        if (total_drained > 0) {
            ESP_LOGD(TAG, "DRAIN: link=%d drained=%d remaining=%d", idx, total_drained, remaining);
        }

        /* Return data, EOF or error if available */
        if (recv_ready_result(s, buf, len, &ret)) return ret;

        /* No data — yield to let lower-priority tasks (DERP connect) run */
        vTaskDelay(1);

    } while ((esp_timer_get_time() - start) < timeout_us);

    /* Timeout */
    errno = EAGAIN;
    return -1;
}

ssize_t ml_at_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }

    if (s->type != SOCK_DGRAM) {
        /* For TCP, just use send */
        return ml_at_send(fd, buf, len, flags);
    }

    char ip_str[INET6_ADDRSTRLEN];  /* 46 bytes — fits IPv4 and IPv6 */
    uint16_t port = 0;
    if (!sockaddr_to_str(dest_addr, addrlen, ip_str, sizeof(ip_str), &port)) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    if (len > AT_MAX_SEND_CHUNK) {
        /* One CIPSEND per datagram: never send a silently truncated one */
        errno = EMSGSIZE;
        return -1;
    }

    /* For UDP, if not yet "connected" (CIPOPEN), open it first */
    if (!s->connected) {
        char cmd[192];
        if (s->local_port > 0) {
            snprintf(cmd, sizeof(cmd), "AT+CIPOPEN=%d,\"UDP\",,,%u",
                     s->link_num, s->local_port);
        } else {
            snprintf(cmd, sizeof(cmd), "AT+CIPOPEN=%d,\"UDP\",,,0",
                     s->link_num);
        }

        AT_LOCK();
        bool ok = (s->link_num >= 0) && at_cmd_ok(cmd, AT_LONG_TIMEOUT_MS);
        AT_UNLOCK();

        if (!ok) {
            ESP_LOGW(TAG, "sendto: CIPOPEN UDP failed for link %d", s->link_num);
            errno = ENETUNREACH;
            return -1;
        }
        s->connected = true;
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    size_t chunk = len;
    char cmd[192];
    snprintf(cmd, sizeof(cmd), "AT+CIPSEND=%d,%d,\"%s\",%u",
             s->link_num, (int)chunk, ip_str, port);

    AT_LOCK();
    if (s->link_num < 0) {          /* closed by another task meanwhile */
        AT_UNLOCK();
        errno = EBADF;
        return -1;
    }

    /* Send command and wait for '>' */
    char resp[256];
    uart_flush_input(UART_NUM);
    char cmd_buf[256];
    snprintf(cmd_buf, sizeof(cmd_buf), "%s\r\n", cmd);
    uart_write_bytes(UART_NUM, cmd_buf, strlen(cmd_buf));

    int resp_len = 0;
    int64_t start = esp_timer_get_time();
    memset(resp, 0, sizeof(resp));
    bool got_prompt = false;
    while ((esp_timer_get_time() - start) < (int64_t)AT_TIMEOUT_MS * 1000) {
        if (resp_len >= (int)sizeof(resp) - 1) break;   /* full: no zero-length spin */
        int n = uart_read_bytes(UART_NUM,
                                 (uint8_t *)(resp + resp_len),
                                 sizeof(resp) - resp_len - 1,
                                 pdMS_TO_TICKS(50));
        if (n > 0) {
            resp_len += n;
            resp[resp_len] = '\0';
            if (strchr(resp, '>')) { got_prompt = true; break; }
            if (strstr(resp, "ERROR")) break;
        }
    }

    if (!got_prompt) {
        AT_UNLOCK();
        ESP_LOGW(TAG, "sendto: no '>' prompt for link %d", s->link_num);
        errno = EIO;
        return -1;
    }

    int sent = at_send_raw(buf, chunk, s->send_timeout_ms);
    AT_UNLOCK();

    if (sent < 0) {
        errno = EIO;
        return -1;
    }

    return chunk;
}

ssize_t ml_at_recvfrom(int fd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }

    ssize_t n = ml_at_recv(fd, buf, len, flags);

    /* Source address from the last +CIPRXGET header that carried one;
     * 0.0.0.0:0 if the modem does not report it (see file header). */
    if (n > 0 && src_addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = s->last_src_ip;
        sin->sin_port = htons(s->last_src_port);
        *addrlen = sizeof(struct sockaddr_in);
    }

    return n;
}

int ml_at_close(int fd)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }

    int idx = fd - AT_SOCK_FD_BASE;
    ESP_LOGI(TAG, "close: fd=%d link=%d", fd, idx);

    /* Send AT+CIPCLOSE */
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "AT+CIPCLOSE=%d", idx);

    /* Hold the UART lock across the close so no RX read can be writing into
     * the ring, then free it under sock_lock so no reader is copying out of
     * it (they re-check link_num/rx_buf under the same lock). */
    AT_LOCK();
    if (s->link_num != idx) {       /* closed by another task meanwhile */
        AT_UNLOCK();
        errno = EBADF;
        return -1;
    }
    at_cmd_ok(cmd, AT_TIMEOUT_MS);

    xSemaphoreTake(s_at.sock_lock, portMAX_DELAY);
    uint8_t *rx_buf = s->rx_buf;
    s->rx_buf = NULL;
    s->rx_head = s->rx_tail = 0;
    s->link_num = -1;
    s->connected = false;
    s->closed_by_remote = false;
    s->rx_error = false;
    xSemaphoreGive(s_at.sock_lock);
    AT_UNLOCK();

    free(rx_buf);
    return 0;
}

int ml_at_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        s->local_port = ntohs(sin->sin_port);
        s->bound = true;
        ESP_LOGD(TAG, "bind: fd=%d port=%u", fd, s->local_port);
    }

    return 0;
}

int ml_at_setsockopt(int fd, int level, int optname,
                      const void *optval, socklen_t optlen)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }

    if (level == SOL_SOCKET) {
        if (optname == SO_RCVTIMEO && optlen >= sizeof(struct timeval)) {
            const struct timeval *tv = (const struct timeval *)optval;
            s->recv_timeout_ms = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (s->recv_timeout_ms == 0) s->recv_timeout_ms = 1; /* Avoid 0 = forever */
            return 0;
        }
        if (optname == SO_SNDTIMEO && optlen >= sizeof(struct timeval)) {
            const struct timeval *tv = (const struct timeval *)optval;
            s->send_timeout_ms = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (s->send_timeout_ms == 0) s->send_timeout_ms = 1;
            return 0;
        }
        if (optname == SO_KEEPALIVE) {
            /* Accepted but can't configure on AT sockets */
            return 0;
        }
    }

    if (level == IPPROTO_TCP) {
        /* TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT — accept but no-op */
        return 0;
    }

    /* Accept unknown options silently */
    return 0;
}

int ml_at_fcntl(int fd, int cmd, int arg)
{
    ml_at_sock_t *s = fd_to_sock(fd);
    if (!s) { errno = EBADF; return -1; }

    if (cmd == F_GETFL) {
        return s->nonblocking ? O_NONBLOCK : 0;
    }

    if (cmd == F_SETFL) {
        s->nonblocking = (arg & O_NONBLOCK) != 0;
        return 0;
    }

    errno = EINVAL;
    return -1;
}

int ml_at_select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout)
{
    uint32_t timeout_ms = 0;
    if (timeout) {
        timeout_ms = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
    } else {
        timeout_ms = 30000; /* Default max 30s instead of forever */
    }

    int ready_count = 0;
    fd_set rd_result, wr_result;
    FD_ZERO(&rd_result);
    FD_ZERO(&wr_result);

    int64_t start = esp_timer_get_time();
    int64_t timeout_us = (int64_t)timeout_ms * 1000;
    bool first_poll = true;

    do {
        ready_count = 0;

        /* First pass: check ring buffers and writable status (no AT commands) */
        for (int fd = AT_SOCK_FD_BASE; fd < AT_SOCK_FD_BASE + AT_SOCK_MAX && fd < nfds; fd++) {
            ml_at_sock_t *s = fd_to_sock(fd);
            if (!s) continue;

            if (readfds && FD_ISSET(fd, readfds)) {
                if (sock_rx_ready(s)) {
                    FD_SET(fd, &rd_result);
                    ready_count++;
                }
            }

            if (writefds && FD_ISSET(fd, writefds)) {
                if (s->connected) {
                    FD_SET(fd, &wr_result);
                    ready_count++;
                }
            }
        }

        if (ready_count > 0) break;

        /* Second pass: query+drain for each socket in one lock hold */
        AT_LOCK();
        for (int fd = AT_SOCK_FD_BASE; fd < AT_SOCK_FD_BASE + AT_SOCK_MAX && fd < nfds; fd++) {
            ml_at_sock_t *s = fd_to_sock(fd);
            if (!s) continue;
            int idx = fd - AT_SOCK_FD_BASE;

            if (readfds && FD_ISSET(fd, readfds) && !sock_rx_ready(s)) {
                int pending = at_query_pending(idx);
                if (pending > 0) {
                    at_read_data(idx, pending, NULL);
                }

                if (sock_rx_ready(s)) {
                    FD_SET(fd, &rd_result);
                    ready_count++;
                }
            }
        }
        AT_UNLOCK();

        if (ready_count > 0) break;

        /* No data — yield to let lower-priority tasks (DERP connect) run,
         * then wait before polling again */
        vTaskDelay(1);

        if (!first_poll) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        first_poll = false;

    } while ((esp_timer_get_time() - start) < timeout_us);

    /* Copy results back */
    if (readfds) *readfds = rd_result;
    if (writefds) *writefds = wr_result;
    if (exceptfds) FD_ZERO(exceptfds);

    return ready_count;
}

/* ============================================================================
 * DNS Resolution
 * ========================================================================== */

int ml_at_getaddrinfo(const char *hostname, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res)
{
    if (!s_at.initialized) return EAI_FAIL;
    if (!hostname) return EAI_NONAME;

    *res = NULL;

    /* Check if hostname is already an IP address */
    struct in_addr test_addr;
    if (inet_aton(hostname, &test_addr)) {
        /* It's already an IP — build result directly */
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
        if (!ai) return EAI_MEMORY;

        struct sockaddr_in *sin = (struct sockaddr_in *)(ai + 1);
        sin->sin_family = AF_INET;
        sin->sin_addr = test_addr;
        if (service) sin->sin_port = htons(atoi(service));

        ai->ai_family = AF_INET;
        ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
        ai->ai_protocol = hints ? hints->ai_protocol : 0;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr *)sin;
        ai->ai_next = NULL;

        *res = ai;
        return 0;
    }

    /* The name goes inside a quoted AT argument: anything but an RFC 1123
     * host name (e.g. a '"' or CR/LF from a web-configured control host or
     * a DERP map entry) could run arbitrary AT commands. */
    if (!ml_at_valid_hostname(hostname)) {
        ESP_LOGW(TAG, "DNS: refusing invalid host name (%u bytes)",
                 (unsigned)strnlen(hostname, 1024));
        return EAI_NONAME;
    }

    /* Resolve via AT+CDNSGIP — this is an ASYNC command.
     * The modem replies "OK" immediately, then sends "+CDNSGIP: 1,..." as a URC.
     * We use at_cmd_wait_urc() to keep reading until we see the result. */
    char cmd[ML_AT_HOSTNAME_MAX + 16];
    snprintf(cmd, sizeof(cmd), "AT+CDNSGIP=\"%s\"", hostname);

    ESP_LOGI(TAG, "DNS: resolving %s", hostname);

    char resp[512];
    AT_LOCK();
    at_cmd_wait_urc(cmd, "+CDNSGIP:", resp, sizeof(resp), DNS_TIMEOUT_MS);
    AT_UNLOCK();

    /* Parse +CDNSGIP: 1,"hostname","IP1"[,"IP2"[,"IP3"]]
     * Also handle error: +CDNSGIP: 0,8 (DNS error code)
     *
     * Some carriers return only IPv6 addresses (e.g. 2001:19F0:...).
     * We iterate through ALL returned IPs, prefer IPv4, fall back to IPv6. */
    char *p = strstr(resp, "+CDNSGIP: 1,");
    if (!p) {
        /* Check for DNS error response */
        char *err_p = strstr(resp, "+CDNSGIP: 0,");
        if (err_p) {
            ESP_LOGW(TAG, "DNS error for %s: %s", hostname, err_p);
        } else {
            ESP_LOGW(TAG, "DNS failed for %s (no +CDNSGIP response): %.*s",
                     hostname, (int)strlen(resp) > 200 ? 200 : (int)strlen(resp), resp);
        }
        return EAI_NONAME;
    }

    /* Extract all quoted IP strings from the response.
     * Format: +CDNSGIP: 1,"hostname","IP1"[,"IP2"[,"IP3"]]
     * Skip the first quoted string (hostname), collect the rest. */
    char *ips[4] = {NULL};
    int ip_count = 0;
    int quote_count = 0;
    char *cur_start = NULL;

    for (char *q = p; *q; q++) {
        if (*q == '"') {
            quote_count++;
            if (quote_count >= 3 && (quote_count % 2) == 1) {
                /* Odd quote >= 3 = start of an IP string */
                cur_start = q + 1;
            } else if (quote_count >= 4 && (quote_count % 2) == 0 && cur_start) {
                /* Even quote >= 4 = end of an IP string */
                *q = '\0';
                if (ip_count < 4) {
                    ips[ip_count++] = cur_start;
                }
                cur_start = NULL;
            }
        }
    }

    if (ip_count == 0) {
        ESP_LOGW(TAG, "DNS parse failed for %s (no IPs found)", hostname);
        return EAI_NONAME;
    }

    /* First pass: look for an IPv4 address (preferred — works with our full stack) */
    for (int i = 0; i < ip_count; i++) {
        if (inet_aton(ips[i], &test_addr)) {
            ESP_LOGI(TAG, "DNS: %s -> %s (IPv4)", hostname, ips[i]);

            struct addrinfo *ai = calloc(1, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
            if (!ai) return EAI_MEMORY;

            struct sockaddr_in *sin = (struct sockaddr_in *)(ai + 1);
            sin->sin_family = AF_INET;
            sin->sin_addr = test_addr;
            if (service) sin->sin_port = htons(atoi(service));

            ai->ai_family = AF_INET;
            ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
            ai->ai_protocol = hints ? hints->ai_protocol : 0;
            ai->ai_addrlen = sizeof(struct sockaddr_in);
            ai->ai_addr = (struct sockaddr *)sin;
            ai->ai_next = NULL;

            *res = ai;
            return 0;
        }
    }

    /* Second pass: no IPv4 found — try IPv6 */
    struct in6_addr addr6;
    for (int i = 0; i < ip_count; i++) {
        if (inet_pton(AF_INET6, ips[i], &addr6) == 1) {
            ESP_LOGI(TAG, "DNS: %s -> %s (IPv6)", hostname, ips[i]);

            struct addrinfo *ai = calloc(1, sizeof(struct addrinfo) + sizeof(struct sockaddr_in6));
            if (!ai) return EAI_MEMORY;

            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(ai + 1);
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = addr6;
            if (service) sin6->sin6_port = htons(atoi(service));

            ai->ai_family = AF_INET6;
            ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
            ai->ai_protocol = hints ? hints->ai_protocol : 0;
            ai->ai_addrlen = sizeof(struct sockaddr_in6);
            ai->ai_addr = (struct sockaddr *)sin6;
            ai->ai_next = NULL;

            *res = ai;
            return 0;
        }
    }

    /* Neither IPv4 nor IPv6 parsed successfully */
    ESP_LOGW(TAG, "DNS parse failed for %s (no valid IPs: %s)", hostname, ips[0]);
    return EAI_NONAME;
}

void ml_at_freeaddrinfo(struct addrinfo *res)
{
    while (res) {
        struct addrinfo *next = res->ai_next;
        free(res);
        res = next;
    }
}

/* ============================================================================
 * Convenience Wrappers (write/read for mbedTLS BIO callbacks)
 * ========================================================================== */

ssize_t ml_at_write(int fd, const void *buf, size_t len)
{
    return ml_at_send(fd, buf, len, 0);
}

ssize_t ml_at_read(int fd, void *buf, size_t len)
{
    return ml_at_recv(fd, buf, len, 0);
}

#endif /* CONFIG_ML_ENABLE_CELLULAR */
