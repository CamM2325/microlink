/**
 * @file ml_derp.c
 * @brief Unified DERP I/O Task + Connection Management
 *
 * Single task handles BOTH reading and writing to DERP TLS connection.
 * This eliminates the need for a TLS mutex since only one task touches
 * the SSL context. Matches v1's single-threaded DERP model.
 *
 * Architecture:
 * - Poll for incoming DERP frames (TLS read) every iteration
 * - Drain TX queue between reads (TLS write)
 * - No mutex needed — single task owns the SSL context exclusively
 *
 * Backpressure strategy (from tailscaled):
 * When queue is full, dequeue oldest packet and retry up to 3 times.
 * If still full, drop the new packet.
 *
 * Reference: tailscale/wgengine/magicsock/derp.go (runDerpWriter)
 *            tailscale/derp/derphttp/derphttp_client.go
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "nacl_box.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *TAG = "ml_derp";

/* Timeout for DERP connection handshake operations */
#define DERP_CONNECT_TIMEOUT_MS  10000

/* ============================================================================
 * Custom BIO callbacks for TLS I/O
 *
 * These wrap the socket layer (ml_read_sock/ml_write_sock) so that both
 * lwIP and AT socket backends work transparently.
 *
 * recv is provided as a blocking recv (f_recv). With the recv_timeout BIO
 * (f_recv_timeout) combined with mbedtls_ssl_conf_read_timeout, the TLS 1.3
 * handshake fails with MBEDTLS_ERR_SSL_BAD_INPUT_DATA (Bad input
 * parameters), so we align with the scheme that already works on the
 * control plane side (coord_bio_recv in ml_coord_tls.c). Timeouts are
 * enforced by SO_RCVTIMEO on the socket; a timeout surfaces as EAGAIN ->
 * MBEDTLS_ERR_SSL_WANT_READ.
 * ========================================================================== */

/**
 * Custom blocking recv for mbedtls BIO (f_recv signature, no timeout arg).
 * SO_RCVTIMEO on the socket bounds the wait; a timeout surfaces as
 * EAGAIN/EWOULDBLOCK which we map to MBEDTLS_ERR_SSL_WANT_READ.
 */
static int ml_derp_bio_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int ret = (int)ml_read_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (ret == 0) {
        return MBEDTLS_ERR_NET_CONN_RESET;
    }
    return ret;
}

/**
 * Custom send for mbedtls BIO.
 */
static int ml_derp_bio_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int ret = (int)ml_write_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

/**
 * Common cleanup for failure paths in ml_derp_connect() after TLS init.
 *
 * Previously we only closed the socket and never freed the mbedTLS
 * contexts, leaking entropy/ctr_drbg/ssl_conf on every connection failure,
 * and — for failures after a successful ssl_setup — the ~20KB TLS I/O
 * buffers as well (internal RAM, since CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC=y).
 * Combined with infinite retries, internal RAM shrank monotonically,
 * making mbedtls_ssl_setup's ALLOC_FAILED -> handshake's Bad input
 * parameters progressively worse on its own. So always free everything.
 *
 * mbedtls_*_free() zeroizes the structs after freeing, so a later
 * ml_derp_disconnect() freeing the same contexts is not a double free.
 */
static void derp_tls_abort(microlink_t *ml, int sock) {
    mbedtls_ssl_free(&ml->derp.ssl);
    mbedtls_ssl_config_free(&ml->derp.ssl_conf);
    mbedtls_ctr_drbg_free(&ml->derp.ctr_drbg);
    mbedtls_entropy_free(&ml->derp.entropy);
    if (sock >= 0) {
        ml_close_sock(sock);
    }
    ml->derp.sockfd = -1;
}

/* DERP frame types */
#define DERP_FRAME_SERVER_KEY   0x01
#define DERP_FRAME_CLIENT_INFO  0x02
#define DERP_FRAME_SERVER_INFO  0x03
#define DERP_FRAME_SEND_PACKET  0x04
#define DERP_FRAME_RECV_PACKET  0x05
#define DERP_FRAME_KEEP_ALIVE   0x06
#define DERP_FRAME_NOTE_PREFERRED 0x07
#define DERP_FRAME_PEER_GONE    0x08
#define DERP_FRAME_PING         0x12
#define DERP_FRAME_PONG         0x13

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

/* ============================================================================
 * TLS Read/Write Helpers
 * ========================================================================== */

/**
 * Read exactly `len` bytes via TLS with timeout and WANT_READ retry.
 * Returns number of bytes read on success, -1 on error, -2 on timeout.
 */
static int derp_tls_read_all(microlink_t *ml, uint8_t *data, size_t len, int timeout_ms) {
    size_t received = 0;
    uint64_t start_ms = ml_get_time_ms();

    while (received < len) {
        if (timeout_ms > 0 && (ml_get_time_ms() - start_ms) > (uint64_t)timeout_ms) {
            ESP_LOGW(TAG, "derp_tls_read_all timeout (%d/%d bytes in %dms)",
                     (int)received, (int)len, timeout_ms);
            return -2;
        }

        int ret = mbedtls_ssl_read(&ml->derp.ssl, data + received, len - received);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ESP_LOGW(TAG, "DERP server closed connection");
                return -1;
            }
            ESP_LOGE(TAG, "TLS read failed: -0x%04x", -ret);
            return -1;
        }
        if (ret == 0) {
            ESP_LOGW(TAG, "TLS connection closed by peer (%d/%d bytes)",
                     (int)received, (int)len);
            return -1;
        }
        received += ret;
    }
    return (int)received;
}

/**
 * Read a DERP frame header (5 bytes: type + 4-byte BE length) with timeout.
 */
static esp_err_t derp_recv_frame_header(microlink_t *ml, uint8_t *type,
                                          uint32_t *len, int timeout_ms) {
    uint8_t header[5];
    int ret = derp_tls_read_all(ml, header, 5, timeout_ms);
    if (ret < 0) {
        return (ret == -2) ? ESP_ERR_TIMEOUT : ESP_FAIL;
    }

    *type = header[0];
    *len = ((uint32_t)header[1] << 24) |
           ((uint32_t)header[2] << 16) |
           ((uint32_t)header[3] << 8) |
           (uint32_t)header[4];

    return ESP_OK;
}

/**
 * Write exactly `len` bytes via TLS with WANT_WRITE retry.
 * Returns bytes written on success, -1 on error.
 * No mutex needed — called only from the DERP I/O task.
 */
static int derp_tls_write_all(microlink_t *ml, const uint8_t *data, size_t len) {
    size_t written = 0;
    int retries = 0;
    const int max_retries = 50;  /* 50 * 10ms = 500ms max */

    while (written < len) {
        int ret = mbedtls_ssl_write(&ml->derp.ssl, data + written, len - written);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                vTaskDelay(pdMS_TO_TICKS(10));
                if (++retries > max_retries) {
                    ESP_LOGW(TAG, "TLS write timeout after %d retries", retries);
                    return -1;
                }
                continue;
            }
            ESP_LOGE(TAG, "TLS write failed: -0x%04x", -ret);
            return -1;
        }
        written += ret;
        retries = 0;
    }
    return (int)written;
}

/* Write a complete DERP frame via TLS */
static int derp_write_frame(microlink_t *ml, uint8_t type,
                             const uint8_t *payload, uint32_t len) {
    /* 5-byte header: 1 type + 4 length (big-endian) */
    uint8_t header[5];
    header[0] = type;
    header[1] = (len >> 24) & 0xFF;
    header[2] = (len >> 16) & 0xFF;
    header[3] = (len >> 8) & 0xFF;
    header[4] = len & 0xFF;

    if (derp_tls_write_all(ml, header, 5) < 0) return -1;

    if (len > 0 && payload) {
        if (derp_tls_write_all(ml, payload, len) < 0) return -1;
    }
    return 0;
}

/* Send a packet to a peer via DERP */
static int derp_send_packet(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    /* SendPacket frame: 32-byte dest key + payload */
    size_t frame_len = 32 + len;
    uint8_t *frame = malloc(frame_len);
    if (!frame) return -1;

    memcpy(frame, dest_key, 32);
    memcpy(frame + 32, data, len);

    int ret = derp_write_frame(ml, DERP_FRAME_SEND_PACKET, frame, frame_len);
    if (ret < 0) {
        ESP_LOGW(TAG, "derp_send_packet FAILED: dest=%02x%02x%02x%02x len=%d",
                 dest_key[0], dest_key[1], dest_key[2], dest_key[3], (int)len);
    }
    free(frame);
    return ret;
}

/* ============================================================================
 * DERP Frame Reading and Dispatch (runs on DERP I/O task)
 * ========================================================================== */

/* Packet classification */
typedef enum {
    PKT_DISCO,
    PKT_STUN,
    PKT_WIREGUARD,
    PKT_UNKNOWN,
} pkt_type_t;

static pkt_type_t classify_packet(const uint8_t *data, size_t len) {
    if (len >= 20 && (data[0] == 0x00 || data[0] == 0x01) && data[1] == 0x01) {
        return PKT_STUN;
    }
    if (len >= 62 && memcmp(data, DISCO_MAGIC, 6) == 0) {
        return PKT_DISCO;
    }
    if (len >= 4) {
        return PKT_WIREGUARD;
    }
    return PKT_UNKNOWN;
}

static void route_derp_packet(microlink_t *ml, uint8_t *data, size_t len,
                               const uint8_t *src_pubkey) {
    pkt_type_t type = classify_packet(data, len);

    ml_rx_packet_t pkt = {
        .data = data,
        .len = len,
        .via_derp = true,
    };
    memcpy(pkt.src_pubkey, src_pubkey, 32);

    QueueHandle_t target = (type == PKT_DISCO) ? ml->disco_rx_queue : ml->wg_rx_queue;
    if (xQueueSend(target, &pkt, 0) != pdTRUE) {
        free(data);
    }
}

/* Dispatch a received DERP frame */
static void dispatch_derp_frame(microlink_t *ml, uint8_t frame_type,
                                 uint8_t *src_key, uint8_t *payload, size_t payload_len) {
    switch (frame_type) {
    case DERP_FRAME_RECV_PACKET:
        if (payload) {
            ESP_LOGI(TAG, "DERP RecvPacket: %d bytes from %02x%02x%02x%02x, hdr=%02x",
                     (int)payload_len,
                     src_key[0], src_key[1], src_key[2], src_key[3],
                     payload_len > 0 ? payload[0] : 0xFF);
            route_derp_packet(ml, payload, payload_len, src_key);
            return;  /* payload ownership transferred */
        }
        break;

    case DERP_FRAME_KEEP_ALIVE:
        ESP_LOGD(TAG, "DERP KeepAlive received");
        break;

    case DERP_FRAME_PING:
        /* Echo ping data back as PONG directly (single-threaded, safe to write) */
        if (payload && payload_len > 0) {
            ESP_LOGD(TAG, "DERP PING received, sending PONG");
            derp_write_frame(ml, DERP_FRAME_PONG, payload, payload_len);
        }
        break;

    case DERP_FRAME_PONG:
        ESP_LOGD(TAG, "DERP PONG received");
        break;

    case DERP_FRAME_PEER_GONE:
        if (payload && payload_len >= 32) {
            ESP_LOGI(TAG, "DERP PeerGone: %02x%02x%02x%02x (len=%d)",
                     payload[0], payload[1], payload[2], payload[3],
                     (int)payload_len);
        }
        break;

    default:
        ESP_LOGD(TAG, "DERP frame type 0x%02x ignored (%d bytes)",
                 frame_type, (int)payload_len);
        break;
    }

    if (payload) free(payload);
}

/**
 * Try to read one DERP frame.
 * SO_RCVTIMEO on the socket bounds each read, so ssl_read never blocks
 * indefinitely (timeout surfaces as WANT_READ from the blocking-recv BIO).
 * Returns: 1 = frame read and dispatched, 0 = timeout (no data), <0 = error
 */
static int poll_derp_read(microlink_t *ml) {
    if (!ml->derp.connected || ml->derp.sockfd < 0) return -1;

    /* Read 5-byte frame header.
     * SO_RCVTIMEO=100ms ensures read() returns within 100ms if no data. */
    uint8_t header[5];
    int n = mbedtls_ssl_read(&ml->derp.ssl, header, 5);
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE ||
        n == MBEDTLS_ERR_SSL_TIMEOUT) {
        return 0;  /* No data available / timeout */
    }
    if (n <= 0) {
        ESP_LOGW(TAG, "DERP header read returned %d (0x%04x)", n, n < 0 ? -n : 0);
        return n;
    }
    if (n < 5) {
        ESP_LOGW(TAG, "DERP partial header: got %d of 5 bytes", n);
        return -1;
    }

    uint8_t frame_type = header[0];
    uint32_t len = (header[1] << 24) | (header[2] << 16) | (header[3] << 8) | header[4];

    uint8_t src_key[32] = {0};
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (len == 0) {
        dispatch_derp_frame(ml, frame_type, src_key, NULL, 0);
        return 1;
    }

    if (len > 65536) {
        ESP_LOGW(TAG, "DERP frame too large: %lu", (unsigned long)len);
        return -1;
    }

    /* Read frame payload - we already got the header so payload should follow.
     * Use longer timeout (2s) since we KNOW data is coming. */
    uint8_t *buf = ml_psram_malloc(len);
    if (!buf) return -1;

    size_t total_read = 0;
    uint64_t payload_start = ml_get_time_ms();
    while (total_read < len) {
        /* Safety timeout: 5 seconds for payload */
        if (ml_get_time_ms() - payload_start > 5000) {
            ESP_LOGW(TAG, "DERP payload timeout at %d/%lu bytes",
                     (int)total_read, (unsigned long)len);
            free(buf);
            return -1;
        }
        n = mbedtls_ssl_read(&ml->derp.ssl, buf + total_read, len - total_read);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE ||
            n == MBEDTLS_ERR_SSL_TIMEOUT) {
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        if (n <= 0) {
            ESP_LOGW(TAG, "DERP payload read error: %d (0x%04x) at %d/%lu bytes",
                     n, n < 0 ? -n : 0, (int)total_read, (unsigned long)len);
            free(buf);
            return n;
        }
        total_read += n;
    }

    /* For RecvPacket (0x05): first 32 bytes are sender's public key */
    if (frame_type == DERP_FRAME_RECV_PACKET && len > 32) {
        memcpy(src_key, buf, 32);
        payload = malloc(len - 32);
        if (payload) {
            memcpy(payload, buf + 32, len - 32);
            payload_len = len - 32;
        }
        free(buf);
    } else {
        payload = buf;
        payload_len = len;
    }

    dispatch_derp_frame(ml, frame_type, src_key, payload, payload_len);
    return 1;
}

/* ============================================================================
 * DERP TX Queue Processing
 * ========================================================================== */

/* Queue a packet for DERP TX with backpressure */
esp_err_t ml_derp_queue_send(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    if (!ml || !dest_key || !data || len == 0) return ESP_ERR_INVALID_ARG;

    uint8_t *pkt_data = malloc(len);
    if (!pkt_data) return ESP_ERR_NO_MEM;
    memcpy(pkt_data, data, len);

    ml_derp_tx_item_t item = {
        .data = pkt_data,
        .len = len,
        .frame_type = DERP_FRAME_SEND_PACKET,
    };
    memcpy(item.dest_pubkey, dest_key, 32);

    /* WG handshake packets (type 1=init, 2=response) get priority — front of queue.
     * This ensures handshake responses aren't delayed behind DISCO pings. */
    bool is_wg_handshake = (len >= 4 && (data[0] == 0x01 || data[0] == 0x02));

    /* Try to send to queue */
    if ((is_wg_handshake ? xQueueSendToFront(ml->derp_tx_queue, &item, 0)
                         : xQueueSend(ml->derp_tx_queue, &item, 0)) == pdTRUE) {
        return ESP_OK;
    }

    /* Queue full - backpressure: drop oldest, retry up to 3 times */
    for (int i = 0; i < 3; i++) {
        ml_derp_tx_item_t dropped;
        if (xQueueReceive(ml->derp_tx_queue, &dropped, 0) == pdTRUE) {
            free(dropped.data);  /* Drop oldest */
        }
        if (xQueueSend(ml->derp_tx_queue, &item, 0) == pdTRUE) {
            return ESP_OK;
        }
    }

    /* Still full after 3 attempts, drop new packet */
    free(pkt_data);
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * Unified DERP I/O Task
 * ========================================================================== */

void ml_derp_tx_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "DERP I/O task started (Core %d)", xPortGetCoreID());

    uint32_t frames_rx = 0;
    uint32_t frames_tx = 0;
    uint64_t last_status_ms = 0;
    uint32_t loop_count = 0;
    uint64_t last_heartbeat_ms = 0;
    uint64_t connected_since_ms = 0;
    bool verbose_phase = false;  /* verbose logging for first 15s after connect */

    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {
        loop_count++;
        uint64_t loop_start = ml_get_time_ms();

        /* Unconditional heartbeat - proves task is alive */
        if (loop_start - last_heartbeat_ms > 5000) {
            ESP_LOGW(TAG, "HEARTBEAT: loop=%lu conn=%d rx=%lu tx=%lu stack_free=%lu",
                     (unsigned long)loop_count, ml->derp.connected,
                     (unsigned long)frames_rx, (unsigned long)frames_tx,
                     (unsigned long)uxTaskGetStackHighWaterMark(NULL));
            last_heartbeat_ms = loop_start;
        }

        /* ---- Periodic status logging (always, even when disconnected) ---- */
        {
            uint64_t now_ms = loop_start;
            if (now_ms - last_status_ms > 10000) {
                ESP_LOGI(TAG, "DERP status: connected=%d fd=%d rx=%lu tx=%lu loops=%lu",
                         ml->derp.connected, ml->derp.sockfd,
                         (unsigned long)frames_rx, (unsigned long)frames_tx,
                         (unsigned long)loop_count);
                last_status_ms = now_ms;
            }
        }

        /* ---- Handle DERP connect request from coord task ---- */
        {
            EventBits_t bits = xEventGroupGetBits(ml->events);
            if ((bits & ML_EVT_DERP_CONNECT_REQ) && !ml->derp.connected) {
                xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECT_REQ);
                /* Retry up to 3 times with 2s backoff */
                for (int attempt = 0; attempt < 3 && !ml->derp.connected; attempt++) {
                    if (attempt > 0) {
                        ESP_LOGW(TAG, "DERP connect retry %d/3 in 2s...", attempt + 1);
                        vTaskDelay(pdMS_TO_TICKS(2000));
                    } else {
                        ESP_LOGI(TAG, "DERP connect requested, connecting from I/O task");
                    }
                    if (ml_derp_connect(ml) == ESP_OK) {
                        connected_since_ms = ml_get_time_ms();
                        verbose_phase = true;
                        break;
                    }
                    ESP_LOGW(TAG, "DERP connect attempt %d failed", attempt + 1);
                }
            }
            if (bits & ML_EVT_DERP_RECONNECT) {
                xEventGroupClearBits(ml->events, ML_EVT_DERP_RECONNECT);
                ESP_LOGW(TAG, "DERP reconnect requested (was %s)",
                         ml->derp.connected ? "connected" : "disconnected");
                ml_derp_disconnect(ml);
                verbose_phase = false;
                /* Auto-reconnect after disconnect */
                vTaskDelay(pdMS_TO_TICKS(1000));
                for (int attempt = 0; attempt < 3 && !ml->derp.connected; attempt++) {
                    if (attempt > 0) {
                        ESP_LOGW(TAG, "DERP reconnect retry %d/3 in 2s...", attempt + 1);
                        vTaskDelay(pdMS_TO_TICKS(2000));
                    }
                    if (ml_derp_connect(ml) == ESP_OK) {
                        connected_since_ms = ml_get_time_ms();
                        verbose_phase = true;
                        break;
                    }
                    ESP_LOGW(TAG, "DERP reconnect attempt %d failed", attempt + 1);
                }
            }
        }

        /* Disable verbose logging after 15s */
        if (verbose_phase && ml_get_time_ms() - connected_since_ms > 15000) {
            verbose_phase = false;
        }

        if (!ml->derp.connected) {
            /* Not connected - just wait and check again */
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* ---- Phase 1: Drain TX queue FIRST (prioritize outgoing) ---- */
        {
            for (int tx_count = 0; tx_count < 8; tx_count++) {
                ml_derp_tx_item_t item;
                if (xQueueReceive(ml->derp_tx_queue, &item, 0) != pdTRUE) {
                    break;
                }
                if (!ml->derp.connected) {
                    free(item.data);
                    continue;
                }
                int ret;
                if (item.frame_type == DERP_FRAME_SEND_PACKET) {
                    ESP_LOGI(TAG, "DERP TX: SendPacket %d bytes, dest=%02x%02x%02x%02x, hdr=%02x",
                             (int)item.len, item.dest_pubkey[0], item.dest_pubkey[1],
                             item.dest_pubkey[2], item.dest_pubkey[3],
                             item.data[0]);
                    ret = derp_send_packet(ml, item.dest_pubkey, item.data, item.len);
                } else {
                    ret = derp_write_frame(ml, item.frame_type, item.data, item.len);
                }
                if (ret < 0) {
                    ESP_LOGW(TAG, "DERP write failed");
                    ml->derp.connected = false;
                    xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
                } else {
                    frames_tx++;
                }
                free(item.data);
            }
        }

        if (!ml->derp.connected) continue;

        /* ---- Phase 2: Poll for incoming DERP frames ---- */
        {
            int burst;
            for (burst = 0; burst < 4; burst++) {
                int ret = poll_derp_read(ml);
                if (ret > 0) {
                    frames_rx++;
                    ml->derp.last_recv_ms = ml_get_time_ms();
                } else if (ret == 0) {
                    break;  /* No more data / timeout */
                } else {
                    ESP_LOGW(TAG, "DERP read error: %d", ret);
                    ml->derp.connected = false;
                    xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
                    break;
                }
            }
        }

        /* Yield briefly */
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    ESP_LOGI(TAG, "DERP I/O task exiting");
    vTaskDelete(NULL);
}

/* ============================================================================
 * DERP Connection Management (called from coord task)
 * ========================================================================== */

esp_err_t ml_derp_connect(microlink_t *ml) {
    /* Determine DERP host/port from DERPMap with node failover.
     * Always start from node 0 (the first/preferred node in the DERPMap).
     * Only rotate to a different node after a SUCCESSFUL connection drops,
     * NOT on connection failure (to avoid bouncing between nodes). */
    const char *derp_host = ML_DERP_HOST;
    int derp_port = ML_DERP_PORT;
    /* Track the region actually used, for logging (differs from HomeDERP on fallback) */
    uint16_t derp_region_used = ml->derp_home_region ? ml->derp_home_region : ML_DERP_REGION;
    bool node_selected = false;

    if (ml->derp_region_count > 0 && ml->derp_home_region > 0) {
        for (int i = 0; i < ml->derp_region_count; i++) {
            if (ml->derp_regions[i].region_id == ml->derp_home_region) {
                /* Always use the first non-stun-only node (preferred node).
                 * This ensures we connect to the same node as most peers. */
                for (int attempt = 0; attempt < ml->derp_regions[i].node_count; attempt++) {
                    if (!ml->derp_regions[i].nodes[attempt].stun_only &&
                        ml->derp_regions[i].nodes[attempt].hostname[0]) {
                        derp_host = ml->derp_regions[i].nodes[attempt].hostname;
                        if (ml->derp_regions[i].nodes[attempt].derp_port > 0) {
                            derp_port = ml->derp_regions[i].nodes[attempt].derp_port;
                        }
                        node_selected = true;
                        break;
                    }
                }
                break;
            }
        }
    }

    /* Fallback for when HomeDERP is not present in the DERPMap.
     * With headscale-based controllers (e.g. ZTL), HomeDERP may still point
     * at an official Tailscale region (e.g. 9) while the DERPMap only
     * contains their own region (e.g. 900). Falling back to the default
     * ML_DERP_HOST (official) in that case is a dead end — neither auth nor
     * TLS succeeds against the official DERP — so instead pick the first
     * usable node (not avoid, not stun-only, has a hostname) from the
     * DERPMap the controller handed out. In the normal official-Tailscale
     * case, HomeDERP is in the DERPMap so node_selected is set and this
     * branch is never taken; behavior is unchanged. */
    if (!node_selected && ml->derp_region_count > 0) {
        for (int i = 0; i < ml->derp_region_count && !node_selected; i++) {
            ml_derp_region_t *r = &ml->derp_regions[i];
            if (r->avoid) continue;
            for (int j = 0; j < r->node_count; j++) {
                if (!r->nodes[j].stun_only && r->nodes[j].hostname[0]) {
                    derp_host = r->nodes[j].hostname;
                    derp_port = (r->nodes[j].derp_port > 0) ? r->nodes[j].derp_port
                                                            : ML_DERP_PORT;
                    derp_region_used = r->region_id;
                    node_selected = true;
                    ESP_LOGW(TAG, "Home DERP region %d not in DERPMap, falling back to region %d (%s)",
                             ml->derp_home_region, derp_region_used, derp_host);
                    break;
                }
            }
        }
    }

    int64_t t_derp_start = esp_timer_get_time();

    ESP_LOGI(TAG, "Connecting to DERP %s:%d (region %d)",
             derp_host, derp_port, derp_region_used);

    /* DNS resolve — accept IPv4 or IPv6 (carrier may be IPv6-only) */
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", derp_port);

    if (ml_getaddrinfo(derp_host, port_str, &hints, &res) != 0 || !res) {
        ESP_LOGE(TAG, "DNS resolve failed for %s", derp_host);
        return ESP_FAIL;
    }

    int64_t t_derp_dns = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP DNS: %lld ms", (t_derp_dns - t_derp_start) / 1000);

    /* TCP connect — use address family from DNS result */
    int sock = ml_socket(res->ai_family, SOCK_STREAM, 0);
    if (sock < 0) {
        ml_freeaddrinfo(res);
        return ESP_FAIL;
    }

    /* Set connect timeout */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (ml_connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        ESP_LOGE(TAG, "TCP connect failed: %d", errno);
        ml_close_sock(sock);
        ml_freeaddrinfo(res);
        return ESP_FAIL;
    }
    ml_freeaddrinfo(res);

    int64_t t_derp_tcp = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP TCP connect: %lld ms", (t_derp_tcp - t_derp_dns) / 1000);

    /* TLS setup */
    mbedtls_ssl_init(&ml->derp.ssl);
    mbedtls_ssl_config_init(&ml->derp.ssl_conf);
    mbedtls_entropy_init(&ml->derp.entropy);
    mbedtls_ctr_drbg_init(&ml->derp.ctr_drbg);

    /* Always check the return values of the mbedTLS setup functions and
     * abort immediately on failure instead of proceeding to the handshake.
     * On failure (typically ALLOC_FAILED), mbedtls_ssl_setup resets
     * ssl->conf to NULL in its error label, so ignoring the error and
     * proceeding to the handshake trips the sanity check with
     * MBEDTLS_ERR_SSL_BAD_INPUT_DATA — misreported as "Bad input
     * parameters" when the real cause is out-of-memory. */
    int cfg_ret;
    cfg_ret = mbedtls_ctr_drbg_seed(&ml->derp.ctr_drbg, mbedtls_entropy_func,
                           &ml->derp.entropy, NULL, 0);
    if (cfg_ret != 0) {
        ESP_LOGE(TAG, "ctr_drbg_seed failed: -0x%04x", -cfg_ret);
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }

    cfg_ret = mbedtls_ssl_config_defaults(&ml->derp.ssl_conf,
                                 MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);
    if (cfg_ret != 0) {
        ESP_LOGE(TAG, "ssl_config_defaults failed: -0x%04x", -cfg_ret);
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }
    mbedtls_ssl_conf_authmode(&ml->derp.ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&ml->derp.ssl_conf, mbedtls_ctr_drbg_random, &ml->derp.ctr_drbg);
    /* Pin the DERP connection to TLS 1.2. When the DERP relay uses a
     * Let's Encrypt ECDSA certificate, the ESP-IDF mbedTLS TLS 1.3 path
     * cannot interpret the certificate's signature algorithm OID and fails
     * with "X509 - Signature algorithm (oid) is unsupported" (even with
     * authmode=VERIFY_NONE, TLS 1.3 cannot skip certificate processing).
     * DERP also accepts TLS 1.2, so pin to 1.2 to bypass the 1.3
     * certificate path. */
    mbedtls_ssl_conf_max_tls_version(&ml->derp.ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);

    cfg_ret = mbedtls_ssl_setup(&ml->derp.ssl, &ml->derp.ssl_conf);
    if (cfg_ret != 0) {
        /* -0x7F00 (ALLOC_FAILED) means internal RAM exhaustion. To allocate
         * the ~20KB TLS I/O buffers from PSRAM instead, set
         * CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC=y. */
        ESP_LOGE(TAG, "mbedtls_ssl_setup failed: -0x%04x", -cfg_ret);
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }
    cfg_ret = mbedtls_ssl_set_hostname(&ml->derp.ssl, derp_host);
    if (cfg_ret != 0) {
        ESP_LOGE(TAG, "ssl_set_hostname failed: -0x%04x", -cfg_ret);
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }
    /* Store socket fd BEFORE setting bio.
     * Use custom BIO callbacks that route through ml_read_sock/ml_write_sock,
     * which transparently support both lwIP and AT socket backends.
     * Timeout is handled via SO_RCVTIMEO. */
    ml->derp.sockfd = sock;
    /* Pass a blocking recv as f_recv and set f_recv_timeout to NULL
     * (same scheme as the control plane; avoids the TLS 1.3 Bad input
     * data failure). */
    mbedtls_ssl_set_bio(&ml->derp.ssl, &ml->derp.sockfd,
                         ml_derp_bio_send, ml_derp_bio_recv, NULL);

    /* TLS handshake - socket has 10s SO_RCVTIMEO from connect phase. */
    int ret;
    while ((ret = mbedtls_ssl_handshake(&ml->derp.ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "TLS handshake failed: %s", err_buf);
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }

    int64_t t_derp_tls = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP TLS handshake: %lld ms", (t_derp_tls - t_derp_tcp) / 1000);
    ESP_LOGI(TAG, "TLS connected to DERP");

    /* HTTP Upgrade: GET /derp with Upgrade: DERP header */
    char upgrade_req[256];
    snprintf(upgrade_req, sizeof(upgrade_req),
             "GET /derp HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: Upgrade\r\n"
             "Upgrade: DERP\r\n"
             "\r\n",
             derp_host);

    ret = mbedtls_ssl_write(&ml->derp.ssl, (const uint8_t *)upgrade_req, strlen(upgrade_req));
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to send HTTP upgrade");
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }

    /* Read HTTP response byte-by-byte until \r\n\r\n to avoid over-reading
     * into the DERP binary frame stream (matching v1 approach) */
    {
        uint8_t resp_buf[512];
        int resp_len = 0;
        bool found_end = false;
        uint64_t http_start = ml_get_time_ms();

        while (resp_len < (int)sizeof(resp_buf) - 1) {
            if (ml_get_time_ms() - http_start > DERP_CONNECT_TIMEOUT_MS) {
                ESP_LOGE(TAG, "HTTP upgrade response timeout");
                derp_tls_abort(ml, sock);
                return ESP_FAIL;
            }

            ret = mbedtls_ssl_read(&ml->derp.ssl, resp_buf + resp_len, 1);
            if (ret < 0) {
                if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                    ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                    vTaskDelay(pdMS_TO_TICKS(10));
                    continue;
                }
                ESP_LOGE(TAG, "HTTP upgrade read failed: -0x%04x", -ret);
                derp_tls_abort(ml, sock);
                return ESP_FAIL;
            }
            if (ret == 0) {
                ESP_LOGE(TAG, "Connection closed during HTTP upgrade");
                derp_tls_abort(ml, sock);
                return ESP_FAIL;
            }
            resp_len++;

            /* Check for \r\n\r\n */
            if (resp_len >= 4 &&
                resp_buf[resp_len - 4] == '\r' && resp_buf[resp_len - 3] == '\n' &&
                resp_buf[resp_len - 2] == '\r' && resp_buf[resp_len - 1] == '\n') {
                found_end = true;
                break;
            }
        }

        resp_buf[resp_len] = '\0';

        if (!found_end || strstr((char *)resp_buf, "101") == NULL) {
            ESP_LOGE(TAG, "DERP upgrade rejected: %.100s", resp_buf);
            derp_tls_abort(ml, sock);
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "HTTP 101 Switching Protocols received");
    }

    /* Match v1 exactly: O_NONBLOCK + short SO_RCVTIMEO + SO_SNDTIMEO.
     * O_NONBLOCK ensures read()/write() never block indefinitely.
     * SO_RCVTIMEO provides 100ms polling rhythm for reads.
     * SO_SNDTIMEO prevents writes from blocking too long. */
    {
        int flags = ml_fcntl(sock, F_GETFL, 0);
        if (flags >= 0) {
            ml_fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
        struct timeval io_tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
        ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &io_tv, sizeof(io_tv));
        ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &io_tv, sizeof(io_tv));
    }

    /* ========================================================
     * DERP Handshake: ServerKey -> ClientInfo -> ServerInfo
     * ======================================================== */

    /* Step 1: Read ServerKey frame header using reliable read helper */
    uint8_t frame_type;
    uint32_t frame_len;
    esp_err_t err = derp_recv_frame_header(ml, &frame_type, &frame_len, DERP_CONNECT_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read ServerKey frame header (err=%d)", err);
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }

    if (frame_type != DERP_FRAME_SERVER_KEY || frame_len < 40) {
        ESP_LOGE(TAG, "Expected ServerKey frame (0x01), got 0x%02x len=%lu",
                 frame_type, (unsigned long)frame_len);
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }

    /* Read and verify 8-byte magic */
    uint8_t magic[8];
    static const uint8_t DERP_MAGIC[8] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};
    if (derp_tls_read_all(ml, magic, 8, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read ServerKey magic");
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }

    if (memcmp(magic, DERP_MAGIC, 8) != 0) {
        ESP_LOGE(TAG, "Invalid DERP magic: %02x%02x%02x%02x%02x%02x%02x%02x",
                 magic[0], magic[1], magic[2], magic[3],
                 magic[4], magic[5], magic[6], magic[7]);
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "DERP magic verified");

    /* Read 32-byte server public key */
    uint8_t derp_server_key[32];
    if (derp_tls_read_all(ml, derp_server_key, 32, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read server key");
        derp_tls_abort(ml, sock);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "DERP server key received (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             derp_server_key[0], derp_server_key[1], derp_server_key[2], derp_server_key[3],
             derp_server_key[4], derp_server_key[5], derp_server_key[6], derp_server_key[7]);

    /* Skip remaining bytes if frame_len > 40 */
    if (frame_len > 40) {
        uint8_t skip_buf[64];
        size_t remaining = frame_len - 40;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(skip_buf) ? sizeof(skip_buf) : remaining;
            if (derp_tls_read_all(ml, skip_buf, chunk, DERP_CONNECT_TIMEOUT_MS) < 0) break;
            remaining -= chunk;
        }
    }

    /* Step 2: Send ClientInfo frame (type 0x02)
     * Payload: [our_nodekey(32)][nonce(24)][nacl_box(JSON)] */
    {
        const char *client_info_json = "{\"Version\":2,\"CanAckPings\":true,\"IsProber\":false}";
        size_t json_len = strlen(client_info_json);

        /* Generate random nonce */
        uint8_t nonce[NACL_BOX_NONCEBYTES];
        esp_fill_random(nonce, NACL_BOX_NONCEBYTES);

        /* Encrypt JSON with NaCl box: our WG private key -> DERP server public key */
        size_t ciphertext_len = json_len + NACL_BOX_MACBYTES;
        uint8_t *ciphertext = malloc(ciphertext_len);
        if (!ciphertext) {
            derp_tls_abort(ml, sock);
            return ESP_FAIL;
        }

        if (nacl_box(ciphertext,
                     (const uint8_t *)client_info_json, json_len,
                     nonce,
                     derp_server_key,       /* recipient: DERP server */
                     ml->wg_private_key     /* sender: our WG node key */
                     ) != 0) {
            ESP_LOGE(TAG, "NaCl box encrypt failed");
            free(ciphertext);
            derp_tls_abort(ml, sock);
            return ESP_FAIL;
        }

        /* Build ClientInfo frame payload: nodekey(32) + nonce(24) + ciphertext */
        size_t ci_payload_len = 32 + NACL_BOX_NONCEBYTES + ciphertext_len;
        uint8_t *ci_payload = malloc(ci_payload_len);
        if (!ci_payload) {
            free(ciphertext);
            derp_tls_abort(ml, sock);
            return ESP_FAIL;
        }

        memcpy(ci_payload, ml->wg_public_key, 32);
        memcpy(ci_payload + 32, nonce, NACL_BOX_NONCEBYTES);
        memcpy(ci_payload + 32 + NACL_BOX_NONCEBYTES, ciphertext, ciphertext_len);
        free(ciphertext);

        ESP_LOGI(TAG, "DERP ClientInfo node_key=%02x%02x%02x%02x%02x%02x%02x%02x",
                 ml->wg_public_key[0], ml->wg_public_key[1],
                 ml->wg_public_key[2], ml->wg_public_key[3],
                 ml->wg_public_key[4], ml->wg_public_key[5],
                 ml->wg_public_key[6], ml->wg_public_key[7]);

        /* Send ClientInfo frame */
        if (derp_write_frame(ml, DERP_FRAME_CLIENT_INFO, ci_payload, ci_payload_len) < 0) {
            ESP_LOGE(TAG, "Failed to send ClientInfo");
            free(ci_payload);
            derp_tls_abort(ml, sock);
            return ESP_FAIL;
        }
        free(ci_payload);

        ESP_LOGI(TAG, "ClientInfo sent");
    }

    /* Step 3: Read ServerInfo frame (type 0x03) */
    {
        uint8_t si_type;
        uint32_t si_len;
        err = derp_recv_frame_header(ml, &si_type, &si_len, DERP_CONNECT_TIMEOUT_MS);
        if (err == ESP_OK && si_type == DERP_FRAME_SERVER_INFO && si_len > 0) {
            /* Read and discard ServerInfo payload */
            uint8_t *si_buf = malloc(si_len);
            if (si_buf) {
                derp_tls_read_all(ml, si_buf, si_len, DERP_CONNECT_TIMEOUT_MS);
                free(si_buf);
            }
            ESP_LOGI(TAG, "ServerInfo received (discarded)");
        } else if (err != ESP_OK) {
            ESP_LOGW(TAG, "No ServerInfo frame (continuing anyway)");
        }
    }

    /* Send NotePreferred (type 0x07): this is our preferred DERP */
    {
        uint8_t preferred = 0x01;
        derp_write_frame(ml, DERP_FRAME_NOTE_PREFERRED, &preferred, 1);
    }

    /* Switch socket to short timeout for data phase.
     * Long timeout was needed for TLS handshake, but polling must be fast.
     * conf_read_timeout is deliberately not called: recv uses the f_recv
     * (blocking) scheme, so only SO_RCVTIMEO takes effect (with
     * f_recv_timeout unused, conf_read_timeout would be a no-op; same
     * policy as the TLS 1.3 Bad input data workaround). */
    {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };  /* 200ms */
        ml_setsockopt(ml->derp.sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    ml->derp.connected = true;
    ml->derp.last_recv_ms = ml_get_time_ms();
    xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECTED);

    int64_t t_derp_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP total: %lld ms (DNS=%lld, TCP=%lld, TLS=%lld, proto=%lld)",
             (t_derp_done - t_derp_start) / 1000,
             (t_derp_dns - t_derp_start) / 1000,
             (t_derp_tcp - t_derp_dns) / 1000,
             (t_derp_tls - t_derp_tcp) / 1000,
             (t_derp_done - t_derp_tls) / 1000);
    ESP_LOGI(TAG, "DERP handshake complete, connected");
    return ESP_OK;
}

void ml_derp_disconnect(microlink_t *ml) {
    ml->derp.connected = false;
    xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);

    if (ml->derp.sockfd >= 0) {
        mbedtls_ssl_close_notify(&ml->derp.ssl);
        mbedtls_ssl_free(&ml->derp.ssl);
        mbedtls_ssl_config_free(&ml->derp.ssl_conf);
        mbedtls_ctr_drbg_free(&ml->derp.ctr_drbg);
        mbedtls_entropy_free(&ml->derp.entropy);
        ml_close_sock(ml->derp.sockfd);
        ml->derp.sockfd = -1;
    }

    /* Drain TX queue */
    ml_derp_tx_item_t item;
    while (xQueueReceive(ml->derp_tx_queue, &item, 0) == pdTRUE) {
        free(item.data);
    }

    ESP_LOGI(TAG, "DERP disconnected");
}
