/**
 * @file ml_coord.c
 * @brief Coordination Task - Control Plane Client
 *
 * Owns ALL Noise protocol state (keys, nonces) exclusively.
 * Handles registration, MapResponse parsing, endpoint updates.
 * Runs as a state machine on Core 1.
 *
 * Protocol flow:
 *   1. DNS resolve controlplane.tailscale.com
 *   2. TCP connect to port 80 (NOT TLS - Noise provides encryption)
 *   3. HTTP/1.1 Upgrade with Noise msg1 in X-Tailscale-Handshake header
 *   4. Read Noise msg2 from upgrade response body
 *   5. Derive transport keys, send H2 preface (encrypted via Noise)
 *   6. Send RegisterRequest (Noise-encrypted H2 HEADERS+DATA)
 *   7. Parse RegisterResponse
 *   8. Send MapRequest, parse MapResponse (peers)
 *   9. Long-poll for updates
 *
 * Reference: tailscale/control/controlclient/auto.go
 *            tailscale/control/controlclient/direct.go
 */

#include "microlink_internal.h"
#include "ml_filter.h"
#include "x25519.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "cJSON.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/ip6_addr.h"
#include "mbedtls/base64.h"
#include <string.h>
#include <errno.h>

static const char *TAG = "ml_coord";

/* Effective control plane host: NVS override or compiled default */
#define CTRL_HOST(ml) ((ml)->ctrl_host[0] ? (ml)->ctrl_host : ML_CTRL_HOST)

/* Coordination state machine */
typedef enum {
    COORD_IDLE,
    COORD_STUN_PROBE,
    COORD_DNS_RESOLVE,
    COORD_TCP_CONNECT,
    COORD_NOISE_HANDSHAKE,
    COORD_H2_PREFACE,
    COORD_REGISTER,
    COORD_FETCH_PEERS,
    COORD_LONG_POLL,
    COORD_RECONNECTING,
} coord_state_t;

/* ============================================================================
 * Helper: hex encoding for keys
 * ========================================================================== */

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    static const char hextab[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hextab[bytes[i] >> 4];
        hex[i * 2 + 1] = hextab[bytes[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}

/* Decimal string for a 64-bit value: newlib-nano printf (CONFIG_NEWLIB_NANO_FORMAT)
 * has no %lld, and tailcfg NodeIDs do not fit in 32 bits. buf: >= 21 bytes. */
static const char *i64_to_str(char *buf, int64_t v) {
    char tmp[20];
    int n = 0;
    uint64_t u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
    do {
        tmp[n++] = (char)('0' + (int)(u % 10));
        u /= 10;
    } while (u);
    char *o = buf;
    if (v < 0) *o++ = '-';
    while (n) *o++ = tmp[--n];
    *o = '\0';
    return buf;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Runs for every node and disco key in a netmap, so no sscanf per byte. */
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    return hex_len / 2;
}

/* Decode a 32-byte key. Only an exact 64-digit hex string counts: on any
 * other input the key is zeroed and false is returned, so a malformed key
 * is never mistaken for a (rotated) key. */
static bool parse_key32(const char *hex, uint8_t key[32]) {
    if (hex_to_bytes(hex, key, 32) == 32) return true;
    memset(key, 0, 32);
    return false;
}

/* ============================================================================
 * TCP I/O helpers for coord socket (owned exclusively by this task)
 * ========================================================================== */

/* SO_RCVTIMEO on the coord socket is never longer than this slice; the
 * timeout a read should honour is kept in ml->coord_st.rcv_timeout_ms and
 * coord_raw_recv() repeats the recv until it expires, checking for shutdown
 * in between. microlink_stop() can shutdown() an lwIP socket to unblock a
 * read, but not an AT-socket fd, where a 60 s recv outlasted the stop
 * timeout and left the coord task (and its context) orphaned. */
#define COORD_RECV_SLICE_MS  1000

/* Set the receive timeout for the coord reads that follow. */
static void coord_set_rcv_timeout(microlink_t *ml, uint32_t ms) {
    if (ms == 0) ms = 1;  /* SO_RCVTIMEO 0 would mean "block forever" */
    ml->coord_st.rcv_timeout_ms = ms;
    uint32_t slice = ms < COORD_RECV_SLICE_MS ? ms : COORD_RECV_SLICE_MS;
    struct timeval tv = { .tv_sec = slice / 1000, .tv_usec = (slice % 1000) * 1000 };
    ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* Single read from the coord transport (recv() semantics), waiting up to
 * ml->coord_st.rcv_timeout_ms. With CONFIG_ML_CTRL_TLS the Noise byte stream
 * runs inside TLS records; timeouts still surface as -1/EAGAIN via the TLS
 * BIO. Returns -1/ECANCELED once shutdown has been requested. */
static int coord_raw_recv(microlink_t *ml, uint8_t *buf, size_t len) {
    uint64_t start_ms = ml_get_time_ms();
    for (;;) {
        uint64_t try_ms = ml_get_time_ms();
#ifdef CONFIG_ML_CTRL_TLS
        int n = ml_coord_tls_recv(ml, buf, len);
#else
        int n = ml_recv(ml->coord_sock, buf, len, 0);
#endif
        if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return n;
        if (ml_shutdown_requested(ml)) {
            errno = ECANCELED;
            return -1;
        }
        uint64_t now = ml_get_time_ms();
        if (now - start_ms >= ml->coord_st.rcv_timeout_ms) {
            errno = EAGAIN;
            return -1;
        }
        if (now - try_ms < 5) {
            vTaskDelay(pdMS_TO_TICKS(10));  /* recv didn't block: don't spin */
        }
    }
}

/* Close the coord connection (TLS session first, then the socket) */
static void coord_close_conn(microlink_t *ml) {
#ifdef CONFIG_ML_CTRL_TLS
    ml_coord_tls_free(ml);
#endif
    if (ml->coord_sock >= 0) {
        ml_close_sock(ml->coord_sock);
        ml->coord_sock = -1;
    }
}

static int coord_send(microlink_t *ml, const uint8_t *data, size_t len) {
    /* Set send timeout to prevent indefinite blocking (v1 uses MSG_DONTWAIT) */
    struct timeval snd_tv = { .tv_sec = 5, .tv_usec = 0 };
    ml_setsockopt(ml->coord_sock, SOL_SOCKET, SO_SNDTIMEO, &snd_tv, sizeof(snd_tv));

#ifdef CONFIG_ML_CTRL_TLS
    if (ml_coord_tls_send(ml, data, len) < 0) {
        ESP_LOGE(TAG, "coord_send (TLS) failed: len=%d errno=%d", (int)len, errno);
        return -1;
    }
    return 0;
#else
    size_t sent = 0;
    while (sent < len) {
        int n = ml_send(ml->coord_sock, data + sent, len - sent, 0);
        if (n <= 0) {
            ESP_LOGE(TAG, "coord_send failed: sent=%d/%d n=%d errno=%d",
                     (int)sent, (int)len, n, errno);
            return -1;
        }
        sent += n;
    }
    return 0;
#endif
}

/* Limits for finishing a read that has started. They are wall-clock times:
 * each retry could block for a full receive timeout (2-60 s), so a retry count
 * gave anything from seconds to hours. STALL bounds the time without any
 * progress, TOTAL the whole read (a 4 KB Noise frame over the ~450 B/s AT
 * socket bridge takes ~10 s). A check runs after each recv returns, so a
 * read can overrun either limit by one receive timeout, and a frame's header
 * and payload reads have separate budgets. The coord watchdog runs on the
 * same task and only sees the result once the read returns. */
#define COORD_RECV_STALL_MS   30000
#define COORD_RECV_TOTAL_MS   90000

/* Read exactly len bytes from the coord transport. Returns 0 or -1.
 *
 * must_complete=false: if the socket times out before the first byte, this
 * returns -1 with errno EAGAIN and nothing consumed, so the caller may try
 * again later. Once a byte has been consumed the read has to finish, or the
 * Noise frame stream is misaligned for good.
 * must_complete=true: the caller already consumed something this read
 * belongs to (a Noise frame header), so even "nothing yet" must finish.
 *
 * A read that has to finish waits at most COORD_RECV_STALL_MS without
 * progress and COORD_RECV_TOTAL_MS in total, and stops on shutdown. Every
 * such failure is a hard error: errno is never EAGAIN then. */
static int coord_recv_ex(microlink_t *ml, uint8_t *buf, size_t len, bool must_complete) {
    size_t recvd = 0;
    uint64_t start_ms = ml_get_time_ms();
    uint64_t progress_ms = start_ms;
    while (recvd < len) {
        int n = coord_raw_recv(ml, buf + recvd, len - recvd);
        if (n == 0) {
            /* Orderly close. recv() leaves errno alone here, and a stale
             * EAGAIN would make callers read this as "no data yet". */
            ESP_LOGW(TAG, "coord_recv: connection closed by peer (recvd %d/%d)",
                     (int)recvd, (int)len);
            errno = ECONNRESET;
            return -1;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (recvd == 0 && !must_complete) {
                    /* No data consumed yet — timeout is fine, caller can retry */
                    return -1;
                }
                uint64_t now = ml_get_time_ms();
                if (ml_shutdown_requested(ml)) {
                    ESP_LOGW(TAG, "coord_recv: shutdown at %d/%d bytes",
                             (int)recvd, (int)len);
                    errno = ECANCELED;
                    return -1;
                }
                if (now - progress_ms > COORD_RECV_STALL_MS ||
                    now - start_ms > COORD_RECV_TOTAL_MS) {
                    ESP_LOGE(TAG, "coord_recv partial timeout: %d/%d bytes after %lu ms",
                             (int)recvd, (int)len, (unsigned long)(now - start_ms));
                    errno = ETIMEDOUT;
                    return -1;
                }
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            int err = errno;  /* logging may clobber it; callers test it */
            if (err == ECANCELED) {
                ESP_LOGI(TAG, "coord_recv: stopping (shutdown requested)");
            } else {
                ESP_LOGE(TAG, "coord_recv failed: %d (errno %d, recvd %d/%d)",
                         n, err, (int)recvd, (int)len);
            }
            errno = err;
            return -1;
        }
        uint64_t now = ml_get_time_ms();
        if (recvd == 0 && !must_complete) {
            start_ms = now;  /* the clock starts with the first byte */
        }
        recvd += n;
        progress_ms = now;
    }
    return 0;
}

static int coord_recv(microlink_t *ml, uint8_t *buf, size_t len) {
    return coord_recv_ex(ml, buf, len, false);
}

/* ============================================================================
 * Noise-encrypted transport I/O
 * ========================================================================== */

/* Send a Noise transport frame: [0x04][len_hi][len_lo][encrypted_data+MAC] */
static int noise_send(microlink_t *ml, ml_noise_state_t *noise,
                        const uint8_t *plaintext, size_t pt_len) {
    size_t ct_len = pt_len + 16;  /* ciphertext + 16-byte MAC */
    uint8_t *frame = ml_psram_malloc(3 + ct_len);
    if (!frame) return -1;

    frame[0] = 0x04;  /* Transport data frame type */
    frame[1] = (ct_len >> 8) & 0xFF;
    frame[2] = ct_len & 0xFF;

    if (ml_noise_encrypt(noise->tx_key, noise->tx_nonce,
                          NULL, 0,
                          plaintext, pt_len,
                          frame + 3) != ESP_OK) {
        free(frame);
        return -1;
    }
    noise->tx_nonce++;

    int ret = coord_send(ml, frame, 3 + ct_len);
    free(frame);
    return ret;
}

/* Read and check a Noise transport frame header: [0x04][len_hi][len_lo].
 * Returns the ciphertext length (>= 16) that noise_recv_payload() must read
 * next, or -1. On -1, errno is EAGAIN only when nothing was consumed (no
 * data yet); every protocol error sets a different errno, since the stream
 * is unusable then. */
#define NOISE_MAX_CT_LEN  (16384 + 16)

static int noise_recv_header(microlink_t *ml) {
    uint8_t hdr[3];
    if (coord_recv(ml, hdr, 3) < 0) return -1;

    if (hdr[0] != 0x04) {
        ESP_LOGE(TAG, "Unexpected Noise frame type: 0x%02x", hdr[0]);
        errno = EBADMSG;
        return -1;
    }

    uint16_t ct_len = (hdr[1] << 8) | hdr[2];
    if (ct_len < 16) {
        ESP_LOGE(TAG, "Noise frame shorter than its MAC: %d", ct_len);
        errno = EBADMSG;
        return -1;
    }
    /* The header is not authenticated, and its length decides how much we
     * allocate before the MAC check. Go's controlbase never writes a frame
     * over 4 KB, so anything past 16 KB is a broken or hostile stream. */
    if (ct_len > NOISE_MAX_CT_LEN) {
        ESP_LOGE(TAG, "Noise frame length %d over the %d limit", ct_len, NOISE_MAX_CT_LEN);
        errno = EMSGSIZE;
        return -1;
    }
    return ct_len;
}

/* Read the ct_len-byte payload of the frame whose header noise_recv_header()
 * just consumed and decrypt it into plaintext (room for ct_len - 16 bytes).
 * Returns the plaintext length, or -1: always a hard error (errno != EAGAIN). */
static int noise_recv_payload(microlink_t *ml, ml_noise_state_t *noise,
                               uint16_t ct_len, uint8_t *plaintext) {
    size_t pt_len = ct_len - 16;
    uint8_t *ciphertext = ml_psram_malloc(ct_len);
    if (!ciphertext) {
        errno = ENOMEM;
        return -1;
    }

    /* Header already consumed — the payload read must complete, in one
     * bounded read. Restarting it from byte 0 after a partial read would
     * lose stream alignment, so any failure here is a hard error. */
    if (coord_recv_ex(ml, ciphertext, ct_len, true) < 0) {
        ESP_LOGE(TAG, "noise_recv payload failed: ct_len=%d errno=%d", ct_len, errno);
        free(ciphertext);
        return -1;
    }

    if (ml_noise_decrypt(noise->rx_key, noise->rx_nonce,
                          NULL, 0,
                          ciphertext, ct_len,
                          plaintext) != ESP_OK) {
        ESP_LOGE(TAG, "Noise decrypt failed (nonce=%lu)", (unsigned long)noise->rx_nonce);
        free(ciphertext);
        errno = EBADMSG;
        return -1;
    }
    noise->rx_nonce++;

    free(ciphertext);
    return (int)pt_len;
}

/* Receive and decrypt a Noise transport frame, returns plaintext length.
 * On -1, errno is EAGAIN only when nothing was consumed (no data yet). */
static int noise_recv(microlink_t *ml, ml_noise_state_t *noise,
                        uint8_t *plaintext, size_t max_len) {
    int ct_len = noise_recv_header(ml);
    if (ct_len < 0) return -1;
    if ((size_t)ct_len - 16 > max_len) {
        ESP_LOGE(TAG, "Noise frame too large: %d > %d", ct_len - 16, (int)max_len);
        errno = EMSGSIZE;
        return -1;
    }
    return noise_recv_payload(ml, noise, (uint16_t)ct_len, plaintext);
}

/* ============================================================================
 * State: DNS_RESOLVE + TCP_CONNECT
 * ========================================================================== */

static int do_tcp_connect(microlink_t *ml) {
    int64_t t_start = esp_timer_get_time();

    ESP_LOGI(TAG, "Resolving %s...", CTRL_HOST(ml));

    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;

#ifdef CONFIG_ML_CTRL_TLS
    const char *ctrl_port = "443";
#else
    const char *ctrl_port = "80";
#endif

    if (ml_getaddrinfo(CTRL_HOST(ml), ctrl_port, &hints, &res) != 0 || !res) {
        ESP_LOGE(TAG, "DNS resolve failed for %s", CTRL_HOST(ml));
        return -1;
    }

    int64_t t_dns = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DNS resolve: %ld ms", (long)((t_dns - t_start) / 1000));

    int sock = ml_socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ml_freeaddrinfo(res);
        ESP_LOGE(TAG, "Socket creation failed");
        return -1;
    }

    /* Socket timeouts */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* TCP keepalive (critical for NAT traversal) */
    int keepalive = 1;
    int keepidle = 25;
    int keepintvl = 10;
    int keepcnt = 3;
    ml_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    ml_setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    ml_setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    ml_setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    ESP_LOGI(TAG, "Connecting to %s:%s...", CTRL_HOST(ml), ctrl_port);

    if (ml_connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        ESP_LOGE(TAG, "TCP connect failed: %d", errno);
        ml_close_sock(sock);
        ml_freeaddrinfo(res);
        return -1;
    }
    ml_freeaddrinfo(res);

    int64_t t_tcp = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] TCP connect: %ld ms (total: %ld ms)",
             (long)((t_tcp - t_dns) / 1000), (long)((t_tcp - t_start) / 1000));

    ml->coord_sock = sock;
    coord_set_rcv_timeout(ml, 10000);  /* same 10 s, now in slices */

#ifdef CONFIG_ML_CTRL_TLS
    if (ml_coord_tls_handshake(ml, CTRL_HOST(ml)) < 0) {
        ml_close_sock(ml->coord_sock);
        ml->coord_sock = -1;
        return -1;
    }
    int64_t t_tls = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] Control TLS handshake: %ld ms", (long)((t_tls - t_tcp) / 1000));
#endif

    return 0;
}

/* ============================================================================
 * State: NOISE_HANDSHAKE (HTTP/1.1 Upgrade with Noise msg1)
 * ========================================================================== */

/* Server proactive data is kept in ml->coord_st.extra_data between the
 * handshake and the H2 preface. */

/* Upper bound for the proactive frames kept from the handshake. EarlyNoise
 * is a few small frames; Go servers never write a frame over 4 KB. */
#define PROACTIVE_MAX_BYTES  16384

/* The read that picked up the proactive frames can end in the middle of
 * one (on slow links HTTP 101, msg2 and part of an EarlyNoise frame arrive
 * in one segment). Read the missing bytes so the buffer ends on a frame
 * boundary: process_proactive_frames() only sees this buffer, and a tail
 * left on the socket would be taken for the next frame header.
 * *buf is replaced when it grows. Returns 0, or -1 if the rest never came. */
static int complete_proactive_frames(microlink_t *ml, uint8_t **buf, int *len) {
    int off = 0;
    for (;;) {
        int need = 0;
        while (off < *len) {
            if (off + 3 > *len) {
                need = off + 3 - *len;          /* frame header cut off */
                break;
            }
            int fl = ((*buf)[off + 1] << 8) | (*buf)[off + 2];
            if (off + 3 + fl > *len) {
                need = off + 3 + fl - *len;     /* frame payload cut off */
                break;
            }
            off += 3 + fl;
        }
        if (need == 0) return 0;

        if (need <= 0 || *len < 0 || *len > PROACTIVE_MAX_BYTES ||
            need > PROACTIVE_MAX_BYTES - *len) {
            ESP_LOGE(TAG, "Proactive frame at offset %d too large (%d bytes missing)", off, need);
            return -1;
        }
        const size_t alloc_len = (size_t)*len + (size_t)need;   /* <= PROACTIVE_MAX_BYTES */
        ESP_LOGI(TAG, "Incomplete proactive frame at offset %d, reading %d more bytes", off, need);
        uint8_t *nb = ml_psram_malloc(alloc_len);
        if (!nb) return -1;
        memcpy(nb, *buf, *len);
        free(*buf);
        *buf = nb;
        if (coord_recv_ex(ml, nb + *len, need, true) < 0) {
            ESP_LOGE(TAG, "Rest of proactive frame did not arrive");
            return -1;
        }
        *len += need;
    }
}

static int do_noise_handshake(microlink_t *ml, ml_noise_state_t *noise) {
    int64_t t_noise_start = esp_timer_get_time();
    /* A challenge belongs to one connection: never answer a previous one. */
    ml->coord_st.has_node_key_challenge = false;

    /* Initialize Noise state with our machine key and the control plane's
     * server key. Priority: config-struct key (runtime, e.g. fetched from
     * https://<control-host>/key?v=131 at provisioning time) >
     * CONFIG_ML_CTRL_NOISE_PUBKEY_HEX (build-time) > built-in Tailscale key. */
    const uint8_t *server_key = NULL;
    if (ml->ctrl_noise_pubkey_set) {
        server_key = ml->ctrl_noise_pubkey;
    }
#ifdef CONFIG_ML_CTRL_NOISE_PUBKEY_HEX
    static uint8_t custom_server_key[32];
    if (!server_key && CONFIG_ML_CTRL_NOISE_PUBKEY_HEX[0] != '\0') {
        if (hex_to_bytes(CONFIG_ML_CTRL_NOISE_PUBKEY_HEX, custom_server_key, 32) == 32) {
            server_key = custom_server_key;
        } else {
            ESP_LOGE(TAG, "Invalid ML_CTRL_NOISE_PUBKEY_HEX (need 64 hex chars) — using built-in key");
        }
    }
#endif
    ml_noise_init(noise,
                   ml->machine_private_key, ml->machine_public_key,
                   server_key);

    /* Build Noise message 1 (101 bytes) */
    uint8_t msg1[128];
    size_t msg1_len = 0;
    if (ml_noise_write_msg1(noise, msg1, &msg1_len) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to build Noise msg1");
        return -1;
    }

    /* Base64 encode msg1 for HTTP header */
    char msg1_b64[256];
    size_t b64_len = 0;
    mbedtls_base64_encode((unsigned char *)msg1_b64, sizeof(msg1_b64), &b64_len,
                           msg1, msg1_len);
    msg1_b64[b64_len] = '\0';

    /* Send HTTP/1.1 Upgrade request with Noise msg1 in header */
    char *http_req = ml_psram_malloc(512 + b64_len);
    if (!http_req) return -1;

    int req_len = snprintf(http_req, 512 + b64_len,
        "POST /ts2021 HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: tailscale-control-protocol\r\n"
        "Connection: Upgrade\r\n"
        "User-Agent: Tailscale\r\n"
        "X-Tailscale-Handshake: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        CTRL_HOST(ml), msg1_b64);

    ESP_LOGI(TAG, "Sending Noise handshake (msg1=%d bytes, b64=%d chars)", (int)msg1_len, (int)b64_len);

    if (coord_send(ml, (uint8_t *)http_req, req_len) < 0) {
        free(http_req);
        return -1;
    }
    free(http_req);

    /* Read HTTP response - use large recv() because server often sends
     * HTTP 101 headers + Noise msg2 + proactive frames in the same TCP segment */
    uint8_t *resp = ml_psram_malloc(2048);
    if (!resp) return -1;

    int total = coord_raw_recv(ml, resp, 2047);
    if (total <= 0) {
        ESP_LOGE(TAG, "Handshake recv failed: %d (errno=%d)", total, errno);
        free(resp);
        return -1;
    }
    resp[total] = '\0';

    ESP_LOGI(TAG, "HTTP response received: %d bytes", total);

    /* Verify 101 Switching Protocols (status line only, not anywhere in the body) */
    if (strncmp((char *)resp, "HTTP/1.1 101", 12) != 0) {
        ESP_LOGE(TAG, "Noise upgrade rejected: %.200s", resp);
        free(resp);
        return -1;
    }
    ESP_LOGI(TAG, "HTTP 101 received, looking for Noise msg2...");

    /* Find end of HTTP headers */
    uint8_t *body_start = (uint8_t *)strstr((char *)resp, "\r\n\r\n");
    if (!body_start) {
        ESP_LOGE(TAG, "No header terminator found");
        free(resp);
        return -1;
    }
    body_start += 4; /* Skip past \r\n\r\n */

    int body_len = total - (body_start - resp);
    ESP_LOGI(TAG, "Body after HTTP headers: %d bytes", body_len);

    /* Copy entire body to working buffer (may contain msg2 + extra frames) */
    uint8_t *body_buf = NULL;
    int body_buf_len = 0;

    if (body_len > 0) {
        /* The 3-byte header read below may write into this buffer even when
         * body_len is 1-2 bytes; never allocate less than it may receive. */
        body_buf = ml_psram_malloc(body_len < 512 ? 512 : body_len);
        if (body_buf) {
            memcpy(body_buf, body_start, body_len);
            body_buf_len = body_len;
        }
    }
    free(resp);

    /* Ensure we have at least the 3-byte Noise frame header */
    if (body_buf_len < 3) {
        ESP_LOGI(TAG, "Reading Noise msg2 header from socket (have %d bytes)...", body_buf_len);
        /* Need to read from socket - allocate buffer if not yet */
        if (!body_buf) {
            body_buf = ml_psram_malloc(512);
            if (!body_buf) return -1;
        }
        if (coord_recv(ml, body_buf + body_buf_len, 3 - body_buf_len) < 0) {
            ESP_LOGE(TAG, "Failed to read Noise msg2 header");
            free(body_buf);
            return -1;
        }
        body_buf_len = 3;
    }

    /* Parse 3-byte Noise frame header */
    uint8_t msg_type = body_buf[0];
    uint16_t payload_len = (body_buf[1] << 8) | body_buf[2];

    ESP_LOGI(TAG, "Noise frame: type=0x%02x, payload_len=%d", msg_type, payload_len);

    if (msg_type != 0x02) {
        ESP_LOGE(TAG, "Unexpected Noise msg type: 0x%02x (expected 0x02)", msg_type);
        free(body_buf);
        return -1;
    }

    /* Noise IK msg2 is exactly the 32-byte ephemeral key + 16-byte tag.
     * Anything else is not a coordinator we understand - refuse it rather
     * than decrypting an attacker-chosen length. */
    if (payload_len != 48) {
        ESP_LOGE(TAG, "Unexpected Noise msg2 length: %d (expected 48)", payload_len);
        free(body_buf);
        return -1;
    }

    int msg2_total = 3 + payload_len;  /* Total msg2 frame size */

    /* Read remaining msg2 payload bytes from socket if needed */
    if (body_buf_len < msg2_total) {
        ESP_LOGI(TAG, "Reading remaining msg2 payload: have %d, need %d", body_buf_len, msg2_total);
        /* Grow buffer if needed */
        uint8_t *tmp = ml_psram_malloc(msg2_total + 512);
        if (!tmp) { free(body_buf); return -1; }
        memcpy(tmp, body_buf, body_buf_len);
        free(body_buf);
        body_buf = tmp;

        if (coord_recv(ml, body_buf + body_buf_len, msg2_total - body_buf_len) < 0) {
            ESP_LOGE(TAG, "Failed to read Noise msg2 payload");
            free(body_buf);
            return -1;
        }
        body_buf_len = msg2_total;
    }

    ESP_LOGI(TAG, "Noise msg2 complete: %d bytes (payload=%d)", msg2_total, payload_len);

    /* Strip 3-byte header, pass raw payload to noise processing */
    if (ml_noise_read_msg2(noise, body_buf + 3, payload_len) != ESP_OK) {
        ESP_LOGE(TAG, "Noise msg2 processing failed");
        free(body_buf);
        return -1;
    }

    int64_t t_noise_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] Noise handshake: %ld ms", (long)((t_noise_done - t_noise_start) / 1000));
    ESP_LOGI(TAG, "Noise handshake complete, transport keys derived");

    /* Save extra data after msg2 (proactive server transport frames)
     * Server sends these immediately after handshake - each one increments
     * server's tx_nonce. We must process them to keep nonces in sync.
     * (Matches v1 g_server_extra_data logic)
     *
     * On fast connections (WiFi), the proactive frames often arrive in
     * the same TCP segment as the HTTP 101 + msg2. On slow connections
     * (cellular PPP), they arrive in separate TCP segments. We must
     * read from the socket if they weren't in the initial buffer. */
    int extra_len = body_buf_len - msg2_total;
    uint8_t *extra_data = NULL;

    if (extra_len > 0) {
        /* Fast path: proactive frames were in the initial recv buffer */
        ESP_LOGI(TAG, "Found %d bytes of extra data after msg2 (proactive frames)", extra_len);
        extra_data = ml_psram_malloc(extra_len);
        if (extra_data) {
            memcpy(extra_data, body_buf + msg2_total, extra_len);
        }
    } else {
        /* Slow path: proactive frames arrive in subsequent TCP segments.
         * Set a short recv timeout and read them from the socket.
         * Server sends EarlyNoise immediately after msg2, so they should
         * arrive within a few hundred ms even on slow cellular links. */
        ESP_LOGI(TAG, "No extra data in initial buffer, reading proactive frames from socket...");
        coord_set_rcv_timeout(ml, 2000);

        extra_data = ml_psram_malloc(1024);
        if (extra_data) {
            int n = coord_raw_recv(ml, extra_data, 1024);
            if (n > 0) {
                extra_len = n;
                ESP_LOGI(TAG, "Read %d bytes of proactive frames from socket", extra_len);
            } else {
                ESP_LOGI(TAG, "No proactive frames from server (n=%d errno=%d)", n, errno);
                free(extra_data);
                extra_data = NULL;
                extra_len = 0;
            }
        }

        /* Restore normal recv timeout */
        coord_set_rcv_timeout(ml, 60000);
    }

    if (extra_data && extra_len > 0 &&
        complete_proactive_frames(ml, &extra_data, &extra_len) < 0) {
        free(extra_data);
        free(body_buf);
        return -1;
    }

    if (extra_data && extra_len > 0) {
        /* Count proactive transport frames */
        int offset = 0;
        int frame_count = 0;
        while (offset + 3 <= extra_len) {
            uint8_t ft = extra_data[offset];
            uint16_t fl = (extra_data[offset + 1] << 8) | extra_data[offset + 2];
            if (offset + 3 + fl > extra_len) {
                ESP_LOGW(TAG, "Incomplete proactive frame at offset %d", offset);
                break;
            }
            ESP_LOGI(TAG, "Proactive frame %d: type=0x%02x, len=%u", frame_count, ft, fl);
            frame_count++;
            offset += 3 + fl;
        }
        ESP_LOGI(TAG, "Server sent %d proactive transport frames", frame_count);

        /* Store for processing after handshake */
        if (ml->coord_st.extra_data) free(ml->coord_st.extra_data);
        ml->coord_st.extra_data = extra_data;
        ml->coord_st.extra_data_len = extra_len;
    } else {
        if (extra_data) free(extra_data);
    }

    free(body_buf);
    return 0;
}

/* ============================================================================
 * Process proactive server frames sent after Noise handshake
 * Copied from v1: decrypt EarlyNoise (frame 0) to get nodeKeyChallenge,
 * then count all frames and set rx_nonce = total count.
 * Frames 1-3 may not decrypt with any nonce/key combo (v1 observation).
 * ========================================================================== */

static void process_proactive_frames(microlink_t *ml, ml_noise_state_t *noise) {
    if (!ml->coord_st.extra_data || ml->coord_st.extra_data_len <= 0) {
        return;
    }

    ESP_LOGI(TAG, "Processing %d bytes of server proactive data", ml->coord_st.extra_data_len);
    ml->coord_st.has_node_key_challenge = false;

    /* Decrypt ALL proactive frames and accumulate plaintext.
     * EarlyNoise content (magic + length + JSON) is split across
     * multiple Noise transport frames:
     *   Frame 0: \xff\xff\xffTS (5 bytes magic)
     *   Frame 1: 4 bytes (big-endian JSON length)
     *   Frame 2: ~95 bytes (JSON with nodeKeyChallenge)
     *   Frame 3: H2 SETTINGS (optional) */
    uint8_t *combined = ml_psram_malloc(1024);
    size_t combined_len = 0;
    int offset = 0;
    int frame_count = 0;
    uint64_t nonce = 0;

    while (offset + 3 <= ml->coord_st.extra_data_len) {
        uint8_t ft = ml->coord_st.extra_data[offset];
        uint16_t fl = (ml->coord_st.extra_data[offset + 1] << 8) | ml->coord_st.extra_data[offset + 2];

        if (offset + 3 + fl > ml->coord_st.extra_data_len) break;

        ESP_LOGI(TAG, "Proactive frame %d: type=0x%02x, len=%u", frame_count, ft, fl);

        if (ft == 0x04 && fl >= ML_NOISE_MAC_LEN && combined) {
            size_t pt_len = fl - ML_NOISE_MAC_LEN;
            uint8_t *plaintext = ml_psram_malloc(pt_len + 1);

            if (plaintext) {
                esp_err_t ret = ml_noise_decrypt(noise->rx_key, nonce,
                                                  NULL, 0,
                                                  ml->coord_st.extra_data + offset + 3, fl,
                                                  plaintext);
                if (ret == ESP_OK) {
                    ESP_LOGI(TAG, "  Decrypted frame %d: %d bytes (nonce=%d)",
                             frame_count, (int)pt_len, (int)nonce);
                    if (combined_len + pt_len < 1024) {
                        memcpy(combined + combined_len, plaintext, pt_len);
                        combined_len += pt_len;
                    }
                } else {
                    ESP_LOGW(TAG, "  Frame %d decrypt failed (nonce=%d)", frame_count, (int)nonce);
                }
                free(plaintext);
            }
        }

        nonce++;
        frame_count++;
        offset += 3 + fl;
    }

    ESP_LOGI(TAG, "Decrypted %d bytes from %d proactive frames", (int)combined_len, frame_count);

    /* Search combined plaintext for nodeKeyChallenge JSON */
    if (combined && combined_len > 0) {
        combined[combined_len < 1024 ? combined_len : 1023] = '\0';

        /* Find JSON start (skip magic + length prefix) */
        char *json_start = NULL;
        for (int i = 0; i < (int)combined_len; i++) {
            if (combined[i] == '{') {
                json_start = (char *)combined + i;
                break;
            }
        }

        if (json_start) {
            ESP_LOGI(TAG, "EarlyNoise JSON: %.80s", json_start);
            cJSON *early_json = cJSON_Parse(json_start);
            if (early_json) {
                cJSON *challenge = cJSON_GetObjectItem(early_json, "nodeKeyChallenge");
                if (challenge && cJSON_IsString(challenge)) {
                    const char *chal_str = challenge->valuestring;
                    ESP_LOGI(TAG, "Found nodeKeyChallenge: %.40s...", chal_str);

                    /* Parse "chalpub:hex..." format (v1 lines 1402-1424) */
                    if (strncmp(chal_str, "chalpub:", 8) == 0) {
                        const char *hex = chal_str + 8;
                        if (parse_key32(hex, ml->coord_st.node_key_challenge)) {
                            ml->coord_st.has_node_key_challenge = true;
                            ESP_LOGI(TAG, "NodeKeyChallenge decoded (32 bytes)");
                        } else {
                            ESP_LOGW(TAG, "NodeKeyChallenge malformed, ignored");
                        }
                    }
                }
                cJSON_Delete(early_json);
            }
        }
    }
    if (combined) free(combined);

    /* Set rx_nonce to skip all proactive frames */
    ESP_LOGI(TAG, "Setting rx_nonce=%d (skipping %d proactive frames)", frame_count, frame_count);
    noise->rx_nonce = frame_count;

    free(ml->coord_st.extra_data);
    ml->coord_st.extra_data = NULL;
    ml->coord_st.extra_data_len = 0;
}

/* ============================================================================
 * State: H2_PREFACE - Send HTTP/2 connection preface (Noise-encrypted)
 * ========================================================================== */

static int do_h2_preface(microlink_t *ml, ml_noise_state_t *noise) {
    int64_t t_h2_start = esp_timer_get_time();

    /* Build H2 preface (24+6=30) + SETTINGS with INITIAL_WINDOW_SIZE (9+6=15)
     * + SETTINGS_ACK (9) + connection-level WINDOW_UPDATE (13) = 67 bytes */
    uint8_t h2_init[128];
    int pos = 0;

    int preface_len = ml_h2_build_preface(h2_init, sizeof(h2_init));
    if (preface_len < 0) return -1;
    pos = preface_len;

    int ack_len = ml_h2_build_settings_ack(h2_init + pos, sizeof(h2_init) - pos);
    if (ack_len < 0) return -1;
    pos += ack_len;

    /* Connection-level WINDOW_UPDATE (stream 0) to expand the connection window
     * beyond the 65535 default. SETTINGS INITIAL_WINDOW_SIZE only sets per-stream
     * window; the connection-level window starts at 65535 and must be explicitly
     * expanded with WINDOW_UPDATE on stream 0. */
    uint32_t conn_window_delta = (ML_H2_BUFFER_SIZE > 65535) ? (ML_H2_BUFFER_SIZE - 65535) : 0;
    if (conn_window_delta > 0) {
        int wu_len = ml_h2_build_window_update(h2_init + pos, sizeof(h2_init) - pos,
                                                0, conn_window_delta);
        if (wu_len > 0) pos += wu_len;
    }

    /* Encrypt and send as one Noise frame */
    if (noise_send(ml, noise, h2_init, pos) < 0) {
        ESP_LOGE(TAG, "Failed to send H2 preface");
        return -1;
    }

    ESP_LOGI(TAG, "H2 preface sent (%d bytes, conn window=%luKB)",
             pos, (unsigned long)(ML_H2_BUFFER_SIZE / 1024));

    /* Read and process server's response (SETTINGS, SETTINGS_ACK, WINDOW_UPDATE, etc.) */
    uint8_t recv_buf[4096];
    int recv_len = noise_recv(ml, noise, recv_buf, sizeof(recv_buf));
    if (recv_len < 0) {
        ESP_LOGW(TAG, "No immediate H2 response from server (may come later)");
        /* Not fatal - server may send its frames later */
    } else {
        ESP_LOGI(TAG, "Server H2 response: %d bytes", recv_len);
    }

    int64_t t_h2_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] H2 preface: %ld ms", (long)((t_h2_done - t_h2_start) / 1000));

    return 0;
}

/* ============================================================================
 * State: REGISTER - Send RegisterRequest, parse RegisterResponse
 * ========================================================================== */

/* do_register: the control plane rejected our auth (vs. -1 = I/O error) */
#define ML_REG_AUTH_FAILED (-2)
#define ML_REG_NEEDS_LOGIN (-3)   /* new AuthURL: the user has to log in */
#define ML_REG_PENDING     (-4)   /* Followup came back before the login was done */

/* How long one Followup request waits for the user to finish logging in
 * before the connection is renewed and the Followup sent again. */
#define ML_LOGIN_FOLLOWUP_WAIT_MS 60000

/* ml->auth_url is written by the coord task and copied out by
 * microlink_get_auth_url() from any task. */
static portMUX_TYPE s_auth_url_lock = portMUX_INITIALIZER_UNLOCKED;

static void set_auth_url(microlink_t *ml, const char *url) {
    taskENTER_CRITICAL(&s_auth_url_lock);
    if (url) {
        strlcpy(ml->auth_url, url, sizeof(ml->auth_url));
    } else {
        ml->auth_url[0] = '\0';
    }
    taskEXIT_CRITICAL(&s_auth_url_lock);
}

esp_err_t microlink_get_auth_url(microlink_t *ml, char *buf, size_t buf_len) {
    if (!ml || !buf || buf_len == 0) return ESP_ERR_INVALID_ARG;
    esp_err_t ret = ESP_OK;
    taskENTER_CRITICAL(&s_auth_url_lock);
    size_t n = strnlen(ml->auth_url, sizeof(ml->auth_url));
    if (n == 0) {
        ret = ESP_ERR_NOT_FOUND;
    } else if (n >= buf_len) {
        ret = ESP_ERR_INVALID_SIZE;
    } else {
        memcpy(buf, ml->auth_url, n + 1);
    }
    taskEXIT_CRITICAL(&s_auth_url_lock);
    return ret;
}

/* An AuthURL is shown to the user (and as a QR code), so accept only a
 * plain http(s) URL of printable ASCII that fits. */
static bool auth_url_ok(const char *url) {
    if (strncmp(url, "https://", 8) != 0 && strncmp(url, "http://", 7) != 0) return false;
    size_t n = strnlen(url, MICROLINK_AUTH_URL_MAX);
    if (n >= MICROLINK_AUTH_URL_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        if (url[i] <= 0x20 || url[i] >= 0x7F) return false;
    }
    return true;
}

/* The IPv6 entry of a node's Addresses ("fd7a:.../128"), if any. */
static bool addresses_ip6(const cJSON *addresses, uint8_t out[16]) {
    const cJSON *a;
    cJSON_ArrayForEach(a, addresses) {
        if (!cJSON_IsString(a) || !strchr(a->valuestring, ':')) continue;
        char buf[48];
        size_t n = strcspn(a->valuestring, "/");
        if (n == 0 || n >= sizeof(buf)) continue;
        memcpy(buf, a->valuestring, n);
        buf[n] = '\0';
        ip6_addr_t ip6;
        if (!ip6addr_aton(buf, &ip6)) continue;
        memcpy(out, ip6.addr, 16);
        return true;
    }
    return false;
}

/* Hostinfo, sent in RegisterRequest and every MapRequest. The control plane
 * reads NetInfo.PreferredDERP from inside it to set Node.HomeDERP for the
 * other peers, and RoutableIPs for subnet routes / exit node. */
static void add_hostinfo(microlink_t *ml, cJSON *root) {
    cJSON *hostinfo = cJSON_CreateObject();
    if (!hostinfo) return;
    const char *dev_name = (ml->config.device_name && ml->config.device_name[0])
                               ? ml->config.device_name : microlink_default_device_name();
    cJSON_AddStringToObject(hostinfo, "Hostname", dev_name);
    cJSON_AddStringToObject(hostinfo, "OS", ML_HOSTINFO_OS);
    cJSON_AddStringToObject(hostinfo, "OSVersion", "ESP-IDF");
    cJSON_AddStringToObject(hostinfo, "GoArch", "arm");

    cJSON *netinfo = cJSON_CreateObject();
    if (netinfo) {
        cJSON_AddNumberToObject(netinfo, "PreferredDERP", ML_DERP_REGION);
        if (ml->stun_nat_checked) {
            cJSON_AddBoolToObject(netinfo, "MappingVariesByDestIP", ml->nat_mapping_varies);
        }
        cJSON_AddItemToObject(hostinfo, "NetInfo", netinfo);
    }

    if (ml->route_count > 0 || ml->route6_count > 0) {
        cJSON *routes = cJSON_CreateArray();
        if (routes) {
            for (int i = 0; i < ml->route_count; i++) {
                char cidr[20];
                ml_routes_format(&ml->routes[i], cidr, sizeof(cidr));
                cJSON_AddItemToArray(routes, cJSON_CreateString(cidr));
            }
            for (int i = 0; i < ml->route6_count; i++) {
                char cidr[48];
                ml_routes6_format(&ml->routes6[i], cidr, sizeof(cidr));
                cJSON_AddItemToArray(routes, cJSON_CreateString(cidr));
            }
            /* Tailscale treats a node as an exit node only when it
             * advertises both default routes (tsaddr.ContainsExitRoutes),
             * as `tailscale up --advertise-exit-node` does. The tunnel is
             * IPv4-only, so IPv6 sent to it is dropped. */
            if (ml_routes_is_exit_node(ml->routes, ml->route_count)) {
                cJSON_AddItemToArray(routes, cJSON_CreateString("::/0"));
            }
            cJSON_AddItemToObject(hostinfo, "RoutableIPs", routes);
        }
    }

    cJSON_AddItemToObject(root, "Hostinfo", hostinfo);
}

static int do_register(microlink_t *ml, ml_noise_state_t *noise) {
    int64_t t_reg_start = esp_timer_get_time();

    /* Build RegisterRequest JSON */
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "Version", ML_CTRL_PROTOCOL_VER);

    /* NodeKey: "nodekey:" + hex(wg_public_key) */
    char key_hex[65];
    char key_str[80];
    bytes_to_hex(ml->wg_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "nodekey:%s", key_hex);
    cJSON_AddStringToObject(root, "NodeKey", key_str);

    /* Interactive login in progress: ask the server to answer once the
     * user has finished (it holds the request until then). Otherwise send
     * the auth key, if there is one; without it the server replies with an
     * AuthURL. */
    bool followup = ml->auth_url[0] != '\0';
    if (followup) {
        cJSON_AddStringToObject(root, "Followup", ml->auth_url);
    } else if (ml->config.auth_key && strlen(ml->config.auth_key) > 0) {
        cJSON *auth = cJSON_CreateObject();
        cJSON_AddStringToObject(auth, "AuthKey", ml->config.auth_key);
        cJSON_AddItemToObject(root, "Auth", auth);
    }

    add_hostinfo(ml, root);

    /* NodeKeyChallengeResponse - prove we own the WireGuard private key
     * Server sends challenge public key in EarlyNoise; we respond with
     * X25519(wg_private_key, challenge_public_key). (v1 lines 1754-1785) */
    if (ml->coord_st.has_node_key_challenge) {
        ESP_LOGI(TAG, "Computing NodeKeyChallengeResponse...");

        /* X25519(wg_private_key, challenge_public_key) */
        uint8_t challenge_pub_copy[32];
        memcpy(challenge_pub_copy, ml->coord_st.node_key_challenge, 32);
        challenge_pub_copy[31] &= 0x7F;  /* Clear high bit per RFC 7748 */

        uint8_t challenge_response[32];
        x25519(challenge_response, ml->wg_private_key, challenge_pub_copy, 1);

        /* Encode as "chalresp:hex..." */
        char chalresp_hex[65];
        bytes_to_hex(challenge_response, 32, chalresp_hex);
        char chalresp_str[80];
        snprintf(chalresp_str, sizeof(chalresp_str), "chalresp:%s", chalresp_hex);
        cJSON_AddStringToObject(root, "NodeKeyChallengeResponse", chalresp_str);
        ESP_LOGI(TAG, "Added NodeKeyChallengeResponse");
    } else {
        ESP_LOGI(TAG, "No nodeKeyChallenge from server (normal for Ionscale)");
    }

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return -1;

    size_t json_len = strlen(json_str);
    ESP_LOGI(TAG, "RegisterRequest: %d bytes", (int)json_len);

    /* Build HTTP/2 HEADERS + DATA frames */
    uint8_t *h2_buf = ml_psram_malloc(json_len + 512);
    if (!h2_buf) { free(json_str); return -1; }

    int h2_pos = 0;

    /* HEADERS frame (POST /machine/register) */
    int hdr_len = ml_h2_build_headers_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                              "POST", "/machine/register",
                                              CTRL_HOST(ml), "application/json",
                                              1, false);
    if (hdr_len < 0) { free(json_str); free(h2_buf); return -1; }
    h2_pos += hdr_len;

    /* DATA frame (JSON body, END_STREAM) */
    int data_len = ml_h2_build_data_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                            (uint8_t *)json_str, json_len,
                                            1, true);
    free(json_str);
    if (data_len < 0) { free(h2_buf); return -1; }
    h2_pos += data_len;

    /* Encrypt and send as one Noise frame */
    if (noise_send(ml, noise, h2_buf, h2_pos) < 0) {
        free(h2_buf);
        return -1;
    }
    free(h2_buf);

    int64_t t_reg_sent = esp_timer_get_time();
    ESP_LOGI(TAG, "RegisterRequest sent (%d H2 bytes) [TIMING] send: %ld ms",
             h2_pos, (long)((t_reg_sent - t_reg_start) / 1000));

    if (followup) coord_set_rcv_timeout(ml, ML_LOGIN_FOLLOWUP_WAIT_MS);

    /* Read RegisterResponse - accumulate all Noise frames into H2 buffer first,
     * then parse H2 frames (same pattern as MapResponse). */
    uint8_t *h2_resp = ml_psram_malloc(16384);
    if (!h2_resp) return -1;
    size_t h2_resp_len = 0;

    uint8_t *resp_buf = ml_psram_malloc(8192);
    if (!resp_buf) { free(h2_resp); return -1; }
    size_t resp_total = 0;

    /* Accumulate Noise frames into H2 buffer.
     * Scan each frame for H2 END_STREAM on stream 1 to break early
     * instead of blocking 60s waiting for more data that won't come. */
    bool got_register_end = false;
    for (int frame_count = 0; frame_count < 10 && !got_register_end; frame_count++) {
        uint8_t *frame_buf = ml_psram_malloc(4096);
        if (!frame_buf) break;

        int frame_len = noise_recv(ml, noise, frame_buf, 4096);
        if (frame_len <= 0) {
            free(frame_buf);
            break;
        }

        ESP_LOGI(TAG, "RegisterResponse Noise frame %d: %d bytes", frame_count, frame_len);

        if (h2_resp_len + frame_len < 16384) {
            memcpy(h2_resp + h2_resp_len, frame_buf, frame_len);
            h2_resp_len += frame_len;
        }
        free(frame_buf);

        /* Scan accumulated buffer for H2 END_STREAM on stream 1 */
        int scan = 0;
        while (scan + 9 <= (int)h2_resp_len) {
            uint32_t fl = (h2_resp[scan] << 16) | (h2_resp[scan+1] << 8) | h2_resp[scan+2];
            uint8_t ft = h2_resp[scan+3];
            uint8_t ff = h2_resp[scan+4];
            uint32_t fs = ((h2_resp[scan+5] & 0x7F) << 24) | (h2_resp[scan+6] << 16) |
                          (h2_resp[scan+7] << 8) | h2_resp[scan+8];
            if (fl > 1000000 || scan + 9 + (int)fl > (int)h2_resp_len) break;
            /* END_STREAM (0x01) on stream 1 in DATA(0x00) or HEADERS(0x01) frame */
            if (fs == 1 && (ft == 0x00 || ft == 0x01) && (ff & 0x01)) {
                got_register_end = true;
                break;
            }
            scan += 9 + fl;
        }
    }

    /* Parse H2 frames from accumulated buffer */
    bool got_end_stream = false;
    int fpos = 0;
    while (fpos + 9 <= (int)h2_resp_len) {
        uint32_t f_len = (h2_resp[fpos] << 16) | (h2_resp[fpos + 1] << 8) | h2_resp[fpos + 2];
        uint8_t f_type = h2_resp[fpos + 3];
        uint8_t f_flags = h2_resp[fpos + 4];
        uint32_t f_stream = ((h2_resp[fpos + 5] & 0x7F) << 24) | (h2_resp[fpos + 6] << 16) |
                             (h2_resp[fpos + 7] << 8) | h2_resp[fpos + 8];
        fpos += 9;

        ESP_LOGD(TAG, "  Register H2 frame: type=%d flags=0x%02x len=%lu stream=%lu",
                 f_type, f_flags, (unsigned long)f_len, (unsigned long)f_stream);

        if (f_len > 1000000 || fpos + (int)f_len > (int)h2_resp_len) {
            ESP_LOGW(TAG, "  Invalid H2 frame length %lu at pos %d, stopping", (unsigned long)f_len, fpos - 9);
            break;
        }

        /* Only process frames on stream 1 (our RegisterResponse).
         * Stream 0 = connection-level (SETTINGS, WINDOW_UPDATE, PING) */
        if (f_stream == 1) {
            if (f_type == 0x00 && f_len > 0) {  /* DATA frame */
                if (resp_total + f_len < 8192) {
                    memcpy(resp_buf + resp_total, h2_resp + fpos, f_len);
                    resp_total += f_len;
                }
                if (f_flags & 0x01) got_end_stream = true;
            }
            if (f_type == 0x01 && (f_flags & 0x01)) got_end_stream = true;
        }

        fpos += f_len;
    }
    (void)got_end_stream;  /* Currently unused for completion detection (suppress -Wunused-but-set-variable) */
    free(h2_resp);

    /* Send connection-level WINDOW_UPDATE for RegisterResponse.
     * Stream 1 is closed (END_STREAM received), only update connection level. */
    if (resp_total > 0) {
        uint8_t wu_buf[13];
        int wu_len = ml_h2_build_window_update(wu_buf, 13, 0, (uint32_t)resp_total);
        noise_send(ml, noise, wu_buf, wu_len);
    }

    ESP_LOGI(TAG, "RegisterResponse: %d bytes total data", (int)resp_total);

    if (resp_total == 0) {
        free(resp_buf);
        if (followup) {
            ESP_LOGI(TAG, "Still waiting for the login");
            return ML_REG_PENDING;
        }
        ESP_LOGW(TAG, "No DATA frame in RegisterResponse");
        /* Not fatal - server may just return headers-only 200 */
        return 0;
    }

    uint8_t *json_data = resp_buf;
    size_t json_data_len = resp_total;

    /* Hex dump first 32 bytes for debugging prefix issues */
    {
        int dump = json_data_len < 32 ? (int)json_data_len : 32;
        char hexbuf[97];
        for (int i = 0; i < dump; i++) {
            sprintf(hexbuf + i * 3, "%02x ", json_data[i]);
        }
        hexbuf[dump * 3] = '\0';
        ESP_LOGI(TAG, "RegisterResponse first %d bytes (hex): %s", dump, hexbuf);
    }


    /* Find start of JSON - skip any binary prefix */
    char *parse_start = (char *)json_data;
    size_t parse_len = json_data_len;
    int json_offset = -1;
    for (int i = 0; i < 8 && i < (int)json_data_len; i++) {
        if (json_data[i] == '{') {
            json_offset = i;
            break;
        }
    }
    if (json_offset > 0) {
        ESP_LOGI(TAG, "RegisterResponse JSON starts at offset %d", json_offset);
        parse_start += json_offset;
        parse_len -= json_offset;
    } else if (json_offset < 0) {
        ESP_LOGW(TAG, "No '{' found in RegisterResponse data");
        free(resp_buf);
        return 0;
    }

    /* Null-terminate for cJSON */
    char saved = parse_start[parse_len];
    parse_start[parse_len] = '\0';

    cJSON *resp_json = cJSON_Parse(parse_start);
    if (!resp_json) {
        ESP_LOGW(TAG, "Failed to parse RegisterResponse JSON (len=%d)", (int)parse_len);
        ESP_LOGW(TAG, "First 100 chars: %.100s", parse_start);
        parse_start[parse_len] = saved;
        free(resp_buf);
        return 0;  /* Not fatal - we'll get peers in MapResponse */
    }
    parse_start[parse_len] = saved;
    free(resp_buf);

    /* The control plane reports auth problems in-band: a non-empty Error or
     * MachineAuthorized=false means the auth key was rejected (expired,
     * revoked, or pending approval). Without this check a rejected
     * registration looks like success and the client spins in the reconnect
     * loop with no way for the host app to tell the user. Return
     * ML_REG_AUTH_FAILED so the coordinator can raise ML_STATE_AUTH_FAILED. */
    cJSON *reg_err = cJSON_GetObjectItem(resp_json, "Error");
    if (reg_err && cJSON_IsString(reg_err) && reg_err->valuestring[0]) {
        ESP_LOGE(TAG, "Registration rejected by control plane: %s", reg_err->valuestring);
        cJSON_Delete(resp_json);
        set_auth_url(ml, NULL);   /* e.g. an expired login: start over */
        return ML_REG_AUTH_FAILED;
    }
    cJSON *authorized = cJSON_GetObjectItem(resp_json, "MachineAuthorized");
    bool is_authorized = authorized && cJSON_IsTrue(authorized);

    /* Interactive login (no auth key): the server sends the URL the user
     * must open, as Tailscale's direct.go handles resp.AuthURL. */
    cJSON *auth_url = cJSON_GetObjectItem(resp_json, "AuthURL");
    if (!is_authorized && cJSON_IsString(auth_url) && auth_url->valuestring[0]) {
        int rc;
        if (!auth_url_ok(auth_url->valuestring)) {
            ESP_LOGE(TAG, "Control plane sent an unusable login URL (%u bytes)",
                     (unsigned)strlen(auth_url->valuestring));
            set_auth_url(ml, NULL);
            rc = ML_REG_AUTH_FAILED;
        } else if (strcmp(ml->auth_url, auth_url->valuestring) != 0) {
            set_auth_url(ml, auth_url->valuestring);
            rc = ML_REG_NEEDS_LOGIN;
        } else {
            rc = ML_REG_PENDING;
        }
        cJSON_Delete(resp_json);
        return rc;
    }
    if (authorized && cJSON_IsFalse(authorized)) {
        cJSON_Delete(resp_json);
        if (followup) {
            ESP_LOGI(TAG, "Login not completed yet");
            return ML_REG_PENDING;
        }
        ESP_LOGE(TAG, "Registration not authorized by control plane");
        return ML_REG_AUTH_FAILED;
    }
    if (followup) {
        ESP_LOGI(TAG, "Interactive login complete");
        set_auth_url(ml, NULL);
    }

    /* Extract our VPN IP from Node.Addresses */
    cJSON *node = cJSON_GetObjectItem(resp_json, "Node");
    if (node) {
        cJSON *addresses = cJSON_GetObjectItem(node, "Addresses");
        if (addresses && addresses_ip6(addresses, ml->vpn_ip6)) ml->has_vpn_ip6 = true;
        if (addresses && cJSON_GetArraySize(addresses) > 0) {
            const char *addr = cJSON_GetArrayItem(addresses, 0)->valuestring;
            if (addr) {
                unsigned a, b, c, d;
                if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                    ml->vpn_ip = (a << 24) | (b << 16) | (c << 8) | d;
                    char ip_str[16];
                    microlink_ip_to_str(ml->vpn_ip, ip_str);
                    ESP_LOGI(TAG, "Our VPN IP: %s", ip_str);
                }
            }
        }
        /* Parse self-node DERP region — try modern HomeDERP (int) first,
         * then fall back to legacy DERP string (format: "127.3.3.40:REGION") */
        cJSON *home_derp = cJSON_GetObjectItem(node, "HomeDERP");
        if (home_derp && cJSON_IsNumber(home_derp) && home_derp->valueint > 0) {
            ml->derp_home_region = (uint16_t)home_derp->valueint;
            ESP_LOGI(TAG, "Home DERP region: %d (from server, HomeDERP)", ml->derp_home_region);
        } else {
            cJSON *self_derp = cJSON_GetObjectItem(node, "DERP");
            if (self_derp && self_derp->valuestring) {
                ESP_LOGI(TAG, "Self-Node DERP: %s", self_derp->valuestring);
                const char *colon = strrchr(self_derp->valuestring, ':');
                if (colon) {
                    int region = atoi(colon + 1);
                    if (region > 0) {
                        ml->derp_home_region = (uint16_t)region;
                        ESP_LOGI(TAG, "Home DERP region: %d (from server, legacy DERP)", region);
                    }
                }
            }
        }
        /* Fallback: if server didn't assign a DERP region, use our configured default */
        if (ml->derp_home_region == 0) {
            ml->derp_home_region = ML_DERP_REGION;
            ESP_LOGI(TAG, "Home DERP region: %d (default)", ML_DERP_REGION);
        }
        cJSON *self_key = cJSON_GetObjectItem(node, "Key");
        if (self_key && self_key->valuestring) {
            ESP_LOGI(TAG, "Self-Node Key (from server): %s", self_key->valuestring);
            char our_key_hex[65];
            bytes_to_hex(ml->wg_public_key, 32, our_key_hex);
            ESP_LOGI(TAG, "Our WG pubkey (local):       nodekey:%s", our_key_hex);
        }
    }

    cJSON_Delete(resp_json);

    int64_t t_reg_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] Register total: %ld ms", (long)((t_reg_done - t_reg_start) / 1000));

    return 0;
}

/* ============================================================================
 * State: FETCH_PEERS - Send MapRequest, parse MapResponse
 * ========================================================================== */

static void log_map_health(cJSON *root);

static void parse_peers_from_map_response(microlink_t *ml, cJSON *root) {
    /* Try all field names used by Tailscale (copied from v1 lines 3176-3184):
     *   "Peers"        - Full peer list (initial Stream=false response)
     *   "PeersChanged" - Incremental updates (Stream=true long-poll)
     *   "peers"        - Lowercase fallback */
    static uint32_t s_netmap_gen = 0;
    bool full_list = false;          /* "Peers" = complete set; "PeersChanged" = delta */
    bool dropped_any = false;
    uint32_t gen = 0;
    cJSON *peers = cJSON_GetObjectItem(root, "Peers");
    if (peers && cJSON_IsArray(peers)) {
        full_list = true;
    }
    if (!peers) {
        peers = cJSON_GetObjectItem(root, "PeersChanged");
        if (peers) ESP_LOGI(TAG, "Using 'PeersChanged' field for peer list");
    }
    if (!peers) {
        peers = cJSON_GetObjectItem(root, "peers");
        if (peers) ESP_LOGI(TAG, "Using 'peers' (lowercase) field for peer list");
        if (peers && cJSON_IsArray(peers)) full_list = true;
    }
    if (full_list) {
        gen = ++s_netmap_gen;
        if (gen == 0) gen = ++s_netmap_gen;   /* 0 means "delta" */
    }
    if (!peers || !cJSON_IsArray(peers)) {
        /* Normal for delta updates (PeersRemoved, PeersChangedPatch only) */
        goto check_removed;
    }

    int count = cJSON_GetArraySize(peers);
    ESP_LOGI(TAG, "MapResponse: %d peers", count);

    cJSON *peer;
    cJSON_ArrayForEach(peer, peers) {
        /* Allocate peer update (freed by wg_mgr after processing) */
        ml_peer_update_t *update = ml_psram_calloc(1, sizeof(ml_peer_update_t));
        if (!update) {
            dropped_any = true;   /* an unqueued peer must not be swept as stale */
            continue;
        }

        update->action = ML_PEER_ADD;
        update->netmap_gen = gen;

        /* tailcfg NodeID - PeersRemoved / PeersChangedPatch refer to peers by it */
        cJSON *node_id = cJSON_GetObjectItem(peer, "ID");
        if (node_id && cJSON_IsNumber(node_id)) {
            update->node_id = (int64_t)node_id->valuedouble;
        }

        /* Hostname */
        cJSON *name = cJSON_GetObjectItem(peer, "Name");
        if (name && name->valuestring) {
            strncpy(update->hostname, name->valuestring, sizeof(update->hostname) - 1);
            /* Strip trailing dot from FQDN */
            size_t hlen = strlen(update->hostname);
            if (hlen > 0 && update->hostname[hlen - 1] == '.') {
                update->hostname[hlen - 1] = '\0';
            }
        }

        /* NodeKey: "nodekey:HEX..." */
        cJSON *key = cJSON_GetObjectItem(peer, "Key");
        if (key && key->valuestring) {
            const char *hex = key->valuestring;
            if (strncmp(hex, "nodekey:", 8) == 0) hex += 8;
            update->key_valid = parse_key32(hex, update->public_key);
            if (!update->key_valid) {
                /* Installing it would give the peer an all-zero key. Drop
                 * the record and keep whatever entry we already have
                 * (dropped_any also stops the full-list sweep evicting it). */
                ESP_LOGW(TAG, "  Peer with malformed Key ignored");
                free(update);
                dropped_any = true;
                continue;
            }
        }

        /* DiscoKey: "discokey:HEX..." */
        cJSON *disco = cJSON_GetObjectItem(peer, "DiscoKey");
        if (disco && disco->valuestring) {
            const char *hex = disco->valuestring;
            if (strncmp(hex, "discokey:", 9) == 0) hex += 9;
            update->disco_valid = parse_key32(hex, update->disco_key);
        }

        /* VPN IP from Addresses */
        cJSON *addresses = cJSON_GetObjectItem(peer, "Addresses");
        if (addresses) update->has_ip6 = addresses_ip6(addresses, update->vpn_ip6);
        if (addresses && cJSON_GetArraySize(addresses) > 0) {
            const char *addr = cJSON_GetArrayItem(addresses, 0)->valuestring;
            if (addr) {
                unsigned a, b, c, d;
                /* Handle CIDR notation (e.g., "100.64.1.2/32") */
                if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                    update->vpn_ip = (a << 24) | (b << 16) | (c << 8) | d;
                }
            }
        }

        /* Online is the control plane's own liveness view. A full peer record
         * always settles it — absent means "not reported", which we take as
         * offline rather than assuming reachable. */
        update->online = cJSON_IsTrue(cJSON_GetObjectItem(peer, "Online"));
        update->online_valid = true;

        /* DERP region — try modern HomeDERP (int) first, then legacy DERP string */
        cJSON *peer_home_derp = cJSON_GetObjectItem(peer, "HomeDERP");
        if (peer_home_derp && cJSON_IsNumber(peer_home_derp) && peer_home_derp->valueint > 0) {
            update->derp_region = (uint16_t)peer_home_derp->valueint;
        } else {
            cJSON *derp = cJSON_GetObjectItem(peer, "DERP");
            if (derp && derp->valuestring) {
                /* Format: "127.3.3.40:N" where N is the region number */
                unsigned dr;
                if (sscanf(derp->valuestring, "127.3.3.40:%u", &dr) == 1) {
                    update->derp_region = (uint16_t)dr;
                }
            }
        }

        /* Endpoints */
        cJSON *endpoints = cJSON_GetObjectItem(peer, "Endpoints");
        if (endpoints) {
            int ep_count = 0;
            cJSON *ep;
            cJSON_ArrayForEach(ep, endpoints) {
                if (ep_count >= ML_MAX_ENDPOINTS) break;
                if (ep->valuestring) {
                    unsigned ea, eb, ec, ed, eport;
                    if (sscanf(ep->valuestring, "%u.%u.%u.%u:%u",
                               &ea, &eb, &ec, &ed, &eport) == 5) {
                        update->endpoints[ep_count].ip =
                            (ea << 24) | (eb << 16) | (ec << 8) | ed;
                        update->endpoints[ep_count].port = (uint16_t)eport;
                        update->endpoints[ep_count].is_ipv6 = false;
                        ep_count++;
                    }
                }
            }
            update->endpoint_count = ep_count;
        }

        char ip_str[16];
        microlink_ip_to_str(update->vpn_ip, ip_str);
        ESP_LOGI(TAG, "  Peer: %s (%s) derp=%d eps=%d",
                 update->hostname, ip_str, update->derp_region, update->endpoint_count);

        /* Send to wg_mgr task via queue */
        ml_wg_mgr_wake(ml);   /* drain while we parse: the queue can fill on big maps */
        if (xQueueSend(ml->peer_update_queue, &update, pdMS_TO_TICKS(100)) != pdTRUE) {
            ESP_LOGW(TAG, "Peer update queue full, dropping %s", update->hostname);
            free(update);
            dropped_any = true;
        }
    }

    /* After a COMPLETE peer list, tell wg_mgr to drop every peer that wasn't
     * in it (removed/revoked nodes, stale NVS-cached peers). Skipped if any
     * add was dropped, so a full queue can never evict a live peer. */
    if (full_list) {
        if (dropped_any) {
            ESP_LOGW(TAG, "Full peer list partially queued; skipping stale-peer sweep");
        } else {
            ml_peer_update_t *done = ml_psram_calloc(1, sizeof(ml_peer_update_t));
            if (done) {
                done->action = ML_PEER_SYNC_DONE;
                done->netmap_gen = gen;
                ml_wg_mgr_wake(ml);   /* drain while we parse: the queue can fill on big maps */
                if (xQueueSend(ml->peer_update_queue, &done, pdMS_TO_TICKS(500)) != pdTRUE) {
                    free(done);
                }
            }
        }
    }

check_removed:
    /* Handle PeersRemoved. Per tailcfg.MapResponse this is []NodeID (integers),
     * which is what Tailscale and Headscale send ("PeersRemoved":[59]). The old
     * code only accepted nodekey strings, so every removal was ignored and a
     * deleted/revoked node kept WireGuard access until reboot. A nodekey string
     * is still accepted as a fallback. */
    cJSON *removed = cJSON_GetObjectItem(root, "PeersRemoved");
    if (removed && cJSON_IsArray(removed)) {
        int rm_count = cJSON_GetArraySize(removed);
        ESP_LOGI(TAG, "PeersRemoved: %d peers", rm_count);

        cJSON *key_item;
        cJSON_ArrayForEach(key_item, removed) {
            bool is_id = cJSON_IsNumber(key_item);
            if (!is_id && !(cJSON_IsString(key_item) && key_item->valuestring)) continue;

            ml_peer_update_t *update = ml_psram_calloc(1, sizeof(ml_peer_update_t));
            if (!update) continue;

            update->action = ML_PEER_REMOVE;
            if (is_id) {
                update->node_id = (int64_t)key_item->valuedouble;
                char id_str[21];
                ESP_LOGI(TAG, "  Remove peer: NodeID %s", i64_to_str(id_str, update->node_id));
            } else {
                const char *hex = key_item->valuestring;
                if (strncmp(hex, "nodekey:", 8) == 0) hex += 8;
                update->key_valid = parse_key32(hex, update->public_key);
                if (!update->key_valid) {
                    ESP_LOGW(TAG, "  PeersRemoved entry with malformed key ignored");
                    free(update);
                    continue;
                }
                ESP_LOGI(TAG, "  Remove peer: %02x%02x%02x%02x...",
                         update->public_key[0], update->public_key[1],
                         update->public_key[2], update->public_key[3]);
            }

            ml_wg_mgr_wake(ml);   /* drain while we parse: the queue can fill on big maps */
            if (xQueueSend(ml->peer_update_queue, &update, pdMS_TO_TICKS(100)) != pdTRUE) {
                free(update);
            }
        }
    }

    /* Handle PeersChangedPatch: per tailcfg this is []*PeerChange, each keyed
     * by NodeID with optional DERPRegion / Endpoints / Online / Key / DiscoKey.
     * (The old code parsed it as an object keyed by nodekey, so every patch -
     * including online/offline transitions and key rotations - was ignored.) */
    cJSON *patches = cJSON_GetObjectItem(root, "PeersChangedPatch");
    if (patches && cJSON_IsArray(patches)) {
        ESP_LOGI(TAG, "PeersChangedPatch: %d changes", cJSON_GetArraySize(patches));
        cJSON *patch;
        cJSON_ArrayForEach(patch, patches) {
            if (cJSON_IsObject(patch)) {
                cJSON *pid = cJSON_GetObjectItem(patch, "NodeID");
                if (!pid || !cJSON_IsNumber(pid)) continue;
                ml_peer_update_t *update = ml_psram_calloc(1, sizeof(ml_peer_update_t));
                if (update) {
                    update->action = ML_PEER_UPDATE_ENDPOINT;
                    update->node_id = (int64_t)pid->valuedouble;

                    cJSON *pkey = cJSON_GetObjectItem(patch, "Key");
                    if (pkey && cJSON_IsString(pkey) && pkey->valuestring) {
                        const char *hex = pkey->valuestring;
                        if (strncmp(hex, "nodekey:", 8) == 0) hex += 8;
                        update->key_valid = parse_key32(hex, update->public_key);
                        if (!update->key_valid) {
                            ESP_LOGW(TAG, "  Patch with malformed Key: key change ignored");
                        }
                    }
                    cJSON *pdisco = cJSON_GetObjectItem(patch, "DiscoKey");
                    if (pdisco && cJSON_IsString(pdisco) && pdisco->valuestring) {
                        const char *hex = pdisco->valuestring;
                        if (strncmp(hex, "discokey:", 9) == 0) hex += 9;
                        update->disco_valid = parse_key32(hex, update->disco_key);
                    }

                    /* Liveness transitions arrive here on the long-poll stream,
                     * so this is what keeps Online fresh between full peer
                     * lists. A patch is partial — an absent field means
                     * "unchanged", not "offline". */
                    cJSON *patch_online = cJSON_GetObjectItem(patch, "Online");
                    if (patch_online) {
                        update->online = cJSON_IsTrue(patch_online);
                        update->online_valid = true;
                    }

                    /* Parse DERP region if present — try DERPRegion (int) first,
                     * then legacy DERP string */
                    cJSON *patch_derp_region = cJSON_GetObjectItem(patch, "DERPRegion");
                    if (patch_derp_region && cJSON_IsNumber(patch_derp_region) && patch_derp_region->valueint > 0) {
                        update->derp_region = (uint16_t)patch_derp_region->valueint;
                    } else {
                        cJSON *derp = cJSON_GetObjectItem(patch, "DERP");
                        if (derp && derp->valuestring) {
                            unsigned dr;
                            if (sscanf(derp->valuestring, "127.3.3.40:%u", &dr) == 1) {
                                update->derp_region = (uint16_t)dr;
                            }
                        }
                    }

                    /* Parse endpoints if present */
                    cJSON *endpoints = cJSON_GetObjectItem(patch, "Endpoints");
                    if (endpoints) {
                        int ep_count = 0;
                        cJSON *ep;
                        cJSON_ArrayForEach(ep, endpoints) {
                            if (ep_count >= ML_MAX_ENDPOINTS) break;
                            if (ep->valuestring) {
                                unsigned ea, eb, ec, ed, eport;
                                if (sscanf(ep->valuestring, "%u.%u.%u.%u:%u",
                                           &ea, &eb, &ec, &ed, &eport) == 5) {
                                    update->endpoints[ep_count].ip =
                                        (ea << 24) | (eb << 16) | (ec << 8) | ed;
                                    update->endpoints[ep_count].port = (uint16_t)eport;
                                    update->endpoints[ep_count].is_ipv6 = false;
                                    ep_count++;
                                }
                            }
                        }
                        update->endpoint_count = ep_count;
                    }

                    char id_str[21];
                    ESP_LOGD(TAG, "  Patch peer: NodeID %s eps=%d key=%d disco=%d",
                             i64_to_str(id_str, update->node_id), update->endpoint_count,
                             update->key_valid, update->disco_valid);

                    ml_wg_mgr_wake(ml);   /* drain while we parse: the queue can fill on big maps */
                    if (xQueueSend(ml->peer_update_queue, &update, pdMS_TO_TICKS(100)) != pdTRUE) {
                        free(update);
                    }
                }
            }
        }
    }
}

/* Add Endpoints + EndpointTypes arrays to a MapRequest JSON object.
 * Includes: WiFi LAN endpoint (type=Local), STUN IPv4 (type=STUN),
 * STUN IPv6 (type=STUN). Returns number of endpoints added. */
static int add_endpoints_to_json(microlink_t *ml, cJSON *root) {
    int count = 0;
    cJSON *ep_array = cJSON_AddArrayToObject(root, "Endpoints");
    cJSON *et_array = cJSON_AddArrayToObject(root, "EndpointTypes");
    if (!ep_array || !et_array) return 0;

    /* LAN endpoint (WiFi station or Ethernet) */
    {
        uint32_t local_ip;
        if (ml_lan_ipv4(&local_ip)) {
            char ep_str[32];
            snprintf(ep_str, sizeof(ep_str), "%lu.%lu.%lu.%lu:%u",
                     (unsigned long)((local_ip >> 24) & 0xFF),
                     (unsigned long)((local_ip >> 16) & 0xFF),
                     (unsigned long)((local_ip >> 8) & 0xFF),
                     (unsigned long)(local_ip & 0xFF),
                     ml->disco_local_port);
            cJSON_AddItemToArray(ep_array, cJSON_CreateString(ep_str));
            cJSON_AddItemToArray(et_array, cJSON_CreateNumber(1));  /* EndpointLocal */
            count++;
        }
    }

    /* PPP endpoint (cellular) — use STUN-discovered public IP as our endpoint */
    /* (PPP netif doesn't have a useful local IP for peers — it's behind CGNAT) */

    /* STUN public endpoint (IPv4) */
    if (ml->stun_public_ip != 0) {
        uint32_t pub_ip = ml->stun_public_ip;
        uint16_t pub_port = ml->stun_public_port ? ml->stun_public_port : ml->disco_local_port;
        char ep_str[32];
        snprintf(ep_str, sizeof(ep_str), "%lu.%lu.%lu.%lu:%u",
                 (unsigned long)((pub_ip >> 24) & 0xFF),
                 (unsigned long)((pub_ip >> 16) & 0xFF),
                 (unsigned long)((pub_ip >> 8) & 0xFF),
                 (unsigned long)(pub_ip & 0xFF),
                 pub_port);
        cJSON_AddItemToArray(ep_array, cJSON_CreateString(ep_str));
        cJSON_AddItemToArray(et_array, cJSON_CreateNumber(2));  /* EndpointSTUN */
        count++;
    }

    /* STUN public endpoint (IPv6) — only include if it's a real IPv6 address,
     * not an IPv4-mapped IPv6 (::ffff:x.x.x.x) which is redundant with IPv4. */
    if (ml->stun_has_ipv6) {
        const uint8_t *a = ml->stun_public_ip6;
        /* Check for IPv4-mapped prefix: first 10 bytes zero, bytes 10-11 = 0xff */
        static const uint8_t v4mapped_prefix[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
        bool is_v4mapped = (memcmp(a, v4mapped_prefix, 12) == 0);
        if (!is_v4mapped) {
            uint16_t port6 = ml->stun_public_port6 ? ml->stun_public_port6 : ml->disco_local_port;
            char ep6_str[64];
            snprintf(ep6_str, sizeof(ep6_str),
                     "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u",
                     a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                     a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
                     port6);
            cJSON_AddItemToArray(ep_array, cJSON_CreateString(ep6_str));
            cJSON_AddItemToArray(et_array, cJSON_CreateNumber(2));  /* EndpointSTUN */
            count++;
        }
    }

    if (count > 0) {
        ESP_LOGI(TAG, "MapRequest includes %d endpoint(s)", count);
    }
    return count;
}

/* Ingest the self-node info (VPN IP / HomeDERP / KeyExpiry / Expired) from
 * a MapResponse. Shared parser called from both paths — the Stream=false
 * one-shot fetch and the streaming_map_fetch initial netmap (extracted from
 * do_fetch_peers). */
static void parse_self_node_from_map(microlink_t *ml, cJSON *map_json) {
    cJSON *node = cJSON_GetObjectItem(map_json, "Node");
    if (!node) return;

    /* Extract VPN IP if not already set */
    if (ml->vpn_ip == 0) {
        cJSON *addresses = cJSON_GetObjectItem(node, "Addresses");
        if (addresses && addresses_ip6(addresses, ml->vpn_ip6)) ml->has_vpn_ip6 = true;
        if (addresses && cJSON_GetArraySize(addresses) > 0) {
            const char *addr = cJSON_GetArrayItem(addresses, 0)->valuestring;
            if (addr) {
                unsigned a, b, c, d;
                if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                    ml->vpn_ip = (a << 24) | (b << 16) | (c << 8) | d;
                    char ip_str[16];
                    microlink_ip_to_str(ml->vpn_ip, ip_str);
                    ESP_LOGI(TAG, "Our VPN IP: %s", ip_str);
                }
            }
        }
    }
    /* Parse self-node DERP region — try modern HomeDERP (int) first,
     * then fall back to legacy DERP string (format: "127.3.3.40:REGION") */
    cJSON *home_derp = cJSON_GetObjectItem(node, "HomeDERP");
    if (home_derp && cJSON_IsNumber(home_derp) && home_derp->valueint > 0) {
        ml->derp_home_region = (uint16_t)home_derp->valueint;
        ESP_LOGI(TAG, "Home DERP region: %d (from server, HomeDERP)", ml->derp_home_region);
    } else {
        cJSON *self_derp = cJSON_GetObjectItem(node, "DERP");
        if (self_derp && self_derp->valuestring) {
            ESP_LOGI(TAG, "Self-Node DERP: %s", self_derp->valuestring);
            const char *colon = strrchr(self_derp->valuestring, ':');
            if (colon) {
                int region = atoi(colon + 1);
                if (region > 0) {
                    ml->derp_home_region = (uint16_t)region;
                    ESP_LOGI(TAG, "Home DERP region: %d (from server, legacy DERP)", region);
                }
            }
        }
    }
    /* Fallback: if server didn't assign a DERP region, use our configured default */
    if (ml->derp_home_region == 0) {
        ml->derp_home_region = ML_DERP_REGION;
        ESP_LOGI(TAG, "Home DERP region: %d (default)", ML_DERP_REGION);
    }
    cJSON *self_key = cJSON_GetObjectItem(node, "Key");
    if (self_key && self_key->valuestring) {
        ESP_LOGI(TAG, "Self-Node Key (server): %.40s...", self_key->valuestring);
        char our_hex[65];
        bytes_to_hex(ml->wg_public_key, 32, our_hex);
        ESP_LOGI(TAG, "Our WG pubkey (local):  nodekey:%.32s...", our_hex);
    }

    /* Parse KeyExpiry (ISO 8601: "YYYY-MM-DDTHH:MM:SSZ") */
    cJSON *key_expiry = cJSON_GetObjectItem(node, "KeyExpiry");
    if (key_expiry && key_expiry->valuestring) {
        int yr, mo, dy, hr, mn, sc;
        if (sscanf(key_expiry->valuestring, "%d-%d-%dT%d:%d:%d",
                   &yr, &mo, &dy, &hr, &mn, &sc) >= 6 &&
            yr >= 1970 && yr <= 2200 && mo >= 1 && mo <= 12 && dy >= 1 && dy <= 31 &&
            hr >= 0 && hr <= 23 && mn >= 0 && mn <= 59 && sc >= 0 && sc <= 60) {
            /* Simple epoch calculation (approximate, no leap second) */
            /* Days from year 1970 */
            int64_t days = 0;
            for (int y = 1970; y < yr; y++) {
                days += (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 366 : 365;
            }
            static const int mdays[] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
            for (int m = 1; m < mo; m++) {
                days += mdays[m];
                if (m == 2 && (yr % 4 == 0 && (yr % 100 != 0 || yr % 400 == 0))) days++;
            }
            days += dy - 1;
            ml->key_expiry_epoch = days * 86400 + hr * 3600 + mn * 60 + sc;
            char epoch_str[21];
            ESP_LOGI(TAG, "Key expiry: %s (epoch: %s)", key_expiry->valuestring,
                     i64_to_str(epoch_str, ml->key_expiry_epoch));
        }
    }

    /* Check Expired flag */
    cJSON *expired = cJSON_GetObjectItem(node, "Expired");
    if (expired && cJSON_IsTrue(expired)) {
        ml->key_expired = true;
        ESP_LOGW(TAG, "Node key is EXPIRED — re-registration needed");
    } else {
        ml->key_expired = false;
    }
}

/* Shared parser that ingests the DERPMap (all regions and nodes) from a
 * MapResponse. Does nothing for MapResponses without a DERPMap (e.g.
 * incremental updates). Called from both the Stream=false one-shot fetch
 * and the streaming_map_fetch path (extracted from do_fetch_peers). */
static void parse_derp_map_from_map(microlink_t *ml, cJSON *map_json) {
    cJSON *derp_map = cJSON_GetObjectItem(map_json, "DERPMap");
    if (!derp_map) return;
    cJSON *regions = cJSON_GetObjectItem(derp_map, "Regions");
    if (!regions) return;

    ml->derp_region_count = 0;
    cJSON *region_obj;
    cJSON_ArrayForEach(region_obj, regions) {
        if (ml->derp_region_count >= ML_MAX_DERP_REGIONS) break;
        ml_derp_region_t *r = &ml->derp_regions[ml->derp_region_count];
        memset(r, 0, sizeof(*r));

        cJSON *rid = cJSON_GetObjectItem(region_obj, "RegionID");
        if (rid) r->region_id = (uint16_t)rid->valuedouble;

        cJSON *rcode = cJSON_GetObjectItem(region_obj, "RegionCode");
        if (rcode && rcode->valuestring) {
            strncpy(r->code, rcode->valuestring, sizeof(r->code) - 1);
        }

        cJSON *avoid = cJSON_GetObjectItem(region_obj, "Avoid");
        if (avoid && cJSON_IsTrue(avoid)) r->avoid = true;

        /* Parse nodes */
        cJSON *nodes = cJSON_GetObjectItem(region_obj, "Nodes");
        if (nodes) {
            cJSON *node_obj;
            cJSON_ArrayForEach(node_obj, nodes) {
                if (r->node_count >= ML_MAX_DERP_NODES) break;
                ml_derp_node_t *n = &r->nodes[r->node_count];
                memset(n, 0, sizeof(*n));

                cJSON *hn = cJSON_GetObjectItem(node_obj, "HostName");
                if (hn && hn->valuestring) {
                    strncpy(n->hostname, hn->valuestring, sizeof(n->hostname) - 1);
                }

                cJSON *ip4 = cJSON_GetObjectItem(node_obj, "IPv4");
                if (ip4 && ip4->valuestring) {
                    strncpy(n->ipv4, ip4->valuestring, sizeof(n->ipv4) - 1);
                }

                cJSON *ip6 = cJSON_GetObjectItem(node_obj, "IPv6");
                if (ip6 && ip6->valuestring) {
                    strncpy(n->ipv6, ip6->valuestring, sizeof(n->ipv6) - 1);
                }

                cJSON *sp = cJSON_GetObjectItem(node_obj, "STUNPort");
                if (sp) n->stun_port = (uint16_t)sp->valuedouble;

                cJSON *dp = cJSON_GetObjectItem(node_obj, "DERPPort");
                if (dp) n->derp_port = (uint16_t)dp->valuedouble;

                cJSON *so = cJSON_GetObjectItem(node_obj, "STUNOnly");
                if (so && cJSON_IsTrue(so)) n->stun_only = true;

                r->node_count++;
            }
        }

        ESP_LOGI(TAG, "  DERP region %d (%s): %d nodes%s",
                 r->region_id, r->code, r->node_count,
                 r->avoid ? " [avoid]" : "");
        for (int ni = 0; ni < r->node_count; ni++) {
            ESP_LOGI(TAG, "    node: %s (v4=%s v6=%s stun=%d derp=%d%s)",
                     r->nodes[ni].hostname,
                     r->nodes[ni].ipv4[0] ? r->nodes[ni].ipv4 : "-",
                     r->nodes[ni].ipv6[0] ? r->nodes[ni].ipv6 : "-",
                     r->nodes[ni].stun_port ? r->nodes[ni].stun_port : 3478,
                     r->nodes[ni].derp_port ? r->nodes[ni].derp_port : 443,
                     r->nodes[ni].stun_only ? " stun-only" : "");
        }

        ml->derp_region_count++;
    }
    ESP_LOGI(TAG, "DERPMap: parsed %d regions", ml->derp_region_count);
}

/* MapResponse bodies are a 4-byte length (little-endian; big-endian also
 * accepted) followed by JSON. Never detect the JSON by looking for '{':
 * the length's low byte is itself '{' (0x7B) whenever length % 256 == 123,
 * which made a netmap of such a size unreadable. The prefix is trusted when
 * it is plausible and the JSON starts right after it; otherwise a body that
 * starts with '{' is taken as JSON without a prefix.
 * Returns the JSON offset (4 or 0) and sets *json_len (0 = unknown, use
 * what is there), or -1 if it is neither. */
static int map_json_offset(const uint8_t *b, size_t have, size_t *json_len) {
    if (have >= 5 && b[4] == '{') {
        size_t le = (size_t)b[0] | ((size_t)b[1] << 8) | ((size_t)b[2] << 16) | ((size_t)b[3] << 24);
        size_t be = ((size_t)b[0] << 24) | ((size_t)b[1] << 16) | ((size_t)b[2] << 8) | (size_t)b[3];
        if (le > 0 && le < ML_JSON_BUFFER_SIZE) { *json_len = le; return 4; }
        if (be > 0 && be < ML_JSON_BUFFER_SIZE) { *json_len = be; return 4; }
    }
    if (have >= 1 && b[0] == '{') { *json_len = 0; return 0; }
    return -1;
}

static int do_fetch_peers(microlink_t *ml, ml_noise_state_t *noise) {
    int64_t t_map_start = esp_timer_get_time();

    /* Build MapRequest JSON */
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "Version", ML_CTRL_PROTOCOL_VER);

    char key_hex[65];
    char key_str[80];
    bytes_to_hex(ml->wg_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "nodekey:%s", key_hex);
    cJSON_AddStringToObject(root, "NodeKey", key_str);

    /* DiscoKey */
    bytes_to_hex(ml->disco_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "discokey:%s", key_hex);
    cJSON_AddStringToObject(root, "DiscoKey", key_str);

    /* Stream=false for initial fetch */
    cJSON_AddBoolToObject(root, "Stream", false);
    cJSON_AddBoolToObject(root, "KeepAlive", true);
    cJSON_AddStringToObject(root, "Compress", "");  /* Disable compression */

    add_hostinfo(ml, root);

    /* Include endpoints if STUN has already completed (Stream=false →
     * control plane processes these, unlike Stream=true with Version >= 68) */
    add_endpoints_to_json(ml, root);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return -1;

    size_t json_len = strlen(json_str);
    ESP_LOGI(TAG, "MapRequest: %d bytes (Stream=false)", (int)json_len);

    /* Build H2 HEADERS + DATA, stream ID 3 (stream 1 was register) */
    uint8_t *h2_buf = ml_psram_malloc(json_len + 512);
    if (!h2_buf) { free(json_str); return -1; }

    int h2_pos = 0;

    int hdr_len = ml_h2_build_headers_frame(h2_buf + h2_pos, json_len + 512,
                                              "POST", "/machine/map",
                                              CTRL_HOST(ml), "application/json",
                                              3, false);
    if (hdr_len < 0) { free(json_str); free(h2_buf); return -1; }
    h2_pos += hdr_len;

    int data_len = ml_h2_build_data_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                            (uint8_t *)json_str, json_len,
                                            3, true);
    free(json_str);
    if (data_len < 0) { free(h2_buf); return -1; }
    h2_pos += data_len;

    if (noise_send(ml, noise, h2_buf, h2_pos) < 0) {
        free(h2_buf);
        return -1;
    }
    free(h2_buf);

    int64_t t_map_sent = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] MapRequest send: %ld ms", (long)((t_map_sent - t_map_start) / 1000));

    /* Read MapResponse - accumulate ALL decrypted Noise frames first, then parse H2.
     * This is critical because a single H2 frame can span multiple Noise frames
     * (v1 does the same with h2_buffer).
     * Smart timeout: extend to 60s for large tailnets (300+ peers = 240KB+). */
    uint8_t *h2_recv = ml_psram_malloc(ML_H2_BUFFER_SIZE);  /* 512KB for 300+ peer tailnets */
    if (!h2_recv) return -1;
    size_t h2_total = 0;

    /* JSON (H2 DATA payloads) is compacted in place into h2_recv after the
     * response is complete, so a second buffer isn't needed. This keeps peak
     * usage to one ML_H2_BUFFER_SIZE allocation, which matters on boards
     * without PSRAM (e.g. ESP32-C3). */
    uint8_t *resp_buf = h2_recv;
    size_t json_total = 0;

    /* Set extended recv timeout for large MapResponse (60 seconds) */
    coord_set_rcv_timeout(ml, 60000);

    uint64_t recv_start_ms = ml_get_time_ms();
    uint64_t last_progress_ms = recv_start_ms;
    size_t window_consumed = 0;

    /* Read all Noise frames and accumulate decrypted H2 data.
     * Scan for H2 END_STREAM flag (0x01) on DATA frames to know when the
     * response is complete — without this, we wait for the full recv timeout
     * (60s) before proceeding, which dominates connection time on cellular. */
    bool got_end_stream = false;
    for (int read_count = 0; read_count < 200; read_count++) {
        /* Decrypt straight into h2_recv (no per-frame 64KB scratch buffer) */
        size_t space = ML_H2_BUFFER_SIZE - h2_total;
        int frame_len = noise_recv(ml, noise, h2_recv + h2_total, space);
        if (frame_len <= 0) {
            if (frame_len < 0 && space < 65536) {
                ESP_LOGW(TAG, "H2 buffer full at %dKB, truncating", (int)(h2_total / 1024));
            }
            break;
        }
        h2_total += frame_len;
        window_consumed += frame_len;

        /* Scan newly accumulated data for H2 END_STREAM flag.
         * H2 frame header: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID.
         * DATA frame type=0x00, END_STREAM flag=0x01.
         * We scan from the start each time since frames may span Noise boundaries. */
        size_t scan_pos = 0;
        while (scan_pos + 9 <= h2_total) {
            uint32_t f_len = (h2_recv[scan_pos] << 16) | (h2_recv[scan_pos + 1] << 8) | h2_recv[scan_pos + 2];
            uint8_t f_type = h2_recv[scan_pos + 3];
            uint8_t f_flags = h2_recv[scan_pos + 4];

            if (scan_pos + 9 + f_len > h2_total) break;  /* Incomplete frame */

            if ((f_type == 0x00 || f_type == 0x01) && (f_flags & 0x01)) {
                /* DATA or HEADERS frame with END_STREAM: response complete.
                 * (Headscale answers a Stream=false request with headers
                 * only - an empty 200 - which used to wait out the 60 s
                 * timeout and then loop forever.) */
                got_end_stream = true;
            }
            scan_pos += 9 + f_len;
        }

        if (got_end_stream) {
            ESP_LOGI(TAG, "H2 END_STREAM detected after %d Noise frames (%dKB, %lums)",
                     read_count + 1, (int)(h2_total / 1024),
                     (unsigned long)(ml_get_time_ms() - recv_start_ms));
            break;
        }

        /* Progress logging every 5 seconds for large responses */
        uint64_t now = ml_get_time_ms();
        if (now - last_progress_ms > 5000) {
            ESP_LOGI(TAG, "MapResponse: received %dKB so far (%d frames, %lums elapsed)",
                     (int)(h2_total / 1024), read_count + 1,
                     (unsigned long)(now - recv_start_ms));
            last_progress_ms = now;
        }

        /* Proactive WINDOW_UPDATE at half our declared stream window to keep
         * the server sending. Must update BOTH connection-level (stream 0) AND
         * stream-level (stream 3) windows, otherwise the server stalls when
         * either window exhausts. Scaled to ML_H2_BUFFER_SIZE (our declared
         * INITIAL_WINDOW_SIZE) instead of a fixed 32KB — a hardcoded 32KB
         * threshold silently truncates responses on configs with a smaller
         * buffer (e.g. 16-32KB on boards without PSRAM): the server exhausts
         * our declared window before this ever fires. */
        if (window_consumed >= ML_H2_BUFFER_SIZE / 2) {
            uint8_t wu_buf[26];  /* 2 WINDOW_UPDATE frames: 13 bytes each */
            int wu_len = ml_h2_build_window_update(wu_buf, 13, 0, (uint32_t)window_consumed);
            wu_len += ml_h2_build_window_update(wu_buf + wu_len, 13, 3, (uint32_t)window_consumed);
            if (wu_len > 0) {
                noise_send(ml, noise, wu_buf, wu_len);
            }
            window_consumed = 0;
        }
    }

    /* Restore normal recv timeout (5 seconds for long-poll) */
    coord_set_rcv_timeout(ml, 5000);

    ESP_LOGI(TAG, "Accumulated %dKB of H2 data from Noise frames (%lums)",
             (int)(h2_total / 1024),
             (unsigned long)(ml_get_time_ms() - recv_start_ms));

    /* Now parse complete H2 frames from accumulated buffer */
    int fpos = 0;
    while (fpos + 9 <= (int)h2_total) {
        uint32_t f_len = (h2_recv[fpos] << 16) | (h2_recv[fpos + 1] << 8) | h2_recv[fpos + 2];
        uint8_t f_type = h2_recv[fpos + 3];
        uint8_t f_flags = h2_recv[fpos + 4];
        uint32_t f_stream = ((h2_recv[fpos + 5] & 0x7F) << 24) |
                            (h2_recv[fpos + 6] << 16) |
                            (h2_recv[fpos + 7] << 8) | h2_recv[fpos + 8];
        fpos += 9;

        ESP_LOGI(TAG, "  H2 frame: type=%d flags=0x%02x len=%lu stream=%lu",
                 f_type, f_flags, (unsigned long)f_len, (unsigned long)f_stream);

        if (fpos + (int)f_len > (int)h2_total) {
            ESP_LOGW(TAG, "  Incomplete H2 frame at end (need %lu, have %d)",
                     (unsigned long)f_len, (int)h2_total - fpos);
            break;
        }

        if (f_type == 0x00 && f_len > 0) {  /* DATA frame */
            /* In-place compaction: json_total <= fpos, so memmove is safe */
            memmove(resp_buf + json_total, h2_recv + fpos, f_len);
            json_total += f_len;
        }

        fpos += f_len;
    }

    /* Send connection-level WINDOW_UPDATE to replenish HTTP/2 flow control.
     * Stream 3 is already closed (END_STREAM received), so only update stream 0.
     * Without this, the server's connection-level window exhausts on large responses. */
    if (json_total > 0) {
        uint8_t wu_buf[13];
        int wu_len = ml_h2_build_window_update(wu_buf, 13, 0, (uint32_t)json_total);
        noise_send(ml, noise, wu_buf, wu_len);
        ESP_LOGI(TAG, "Sent H2 WINDOW_UPDATE: %d bytes (connection level)", (int)json_total);
    }

    if (json_total == 0) {
        ESP_LOGW(TAG, "Empty MapResponse");
        free(resp_buf);
        return -2;   /* server ignores Stream=false: caller switches to streaming */
    }

    ESP_LOGI(TAG, "MapResponse JSON: %d bytes", (int)json_total);

    /* Give the unused tail of the receive buffer back to the heap before
     * cJSON builds its DOM (+1 for the null terminator below). */
    {
        uint8_t *shrunk = realloc(resp_buf, json_total + 1);
        if (shrunk) resp_buf = shrunk;
    }

    /* Hex dump first 32 bytes for debugging prefix issues */
    {
        int dump = json_total < 32 ? (int)json_total : 32;
        char hexbuf[97];
        for (int i = 0; i < dump; i++) {
            sprintf(hexbuf + i * 3, "%02x ", resp_buf[i]);
        }
        hexbuf[dump * 3] = '\0';
        ESP_LOGI(TAG, "MapResponse first %d bytes (hex): %s", dump, hexbuf);
    }

    /* Length prefix (4 bytes, little-endian) before the JSON: see map_json_offset */
    char *parse_start = (char *)resp_buf;
    size_t parse_len = json_total;
    size_t prefixed_len = 0;
    int json_offset = map_json_offset(resp_buf, json_total, &prefixed_len);
    if (json_offset > 0) {
        ESP_LOGI(TAG, "JSON starts at offset %d (skipping %d-byte prefix)", json_offset, json_offset);
        parse_start += json_offset;
        parse_len -= json_offset;
        if (prefixed_len > 0 && prefixed_len < parse_len) parse_len = prefixed_len;  /* this message only */
    } else if (json_offset < 0) {
        ESP_LOGW(TAG, "MapResponse is neither length-prefixed nor plain JSON");
    }

    /* Null-terminate */
    char saved = parse_start[parse_len];
    parse_start[parse_len] = '\0';

    cJSON *map_json = cJSON_Parse(parse_start);
    parse_start[parse_len] = saved;

    /* Raw JSON is no longer needed once the DOM exists — free it early */
    free(resp_buf);
    resp_buf = NULL;

    if (!map_json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "MapResponse JSON parse failed near: %.50s", err ? err : "unknown");
        free(resp_buf);
        return -1;
    }

    /* Debug: log all top-level fields in MapResponse (from v1 lines 3053-3072) */
    {
        log_map_health(map_json);
        ESP_LOGI(TAG, "MapResponse top-level fields:");
        cJSON *field = NULL;
        cJSON_ArrayForEach(field, map_json) {
            if (field->string) {
                if (cJSON_IsArray(field))
                    ESP_LOGI(TAG, "  - %s (array, size=%d)", field->string, cJSON_GetArraySize(field));
                else if (cJSON_IsObject(field))
                    ESP_LOGI(TAG, "  - %s (object)", field->string);
                else if (cJSON_IsString(field))
                    ESP_LOGI(TAG, "  - %s (string): %.40s", field->string, field->valuestring);
                else if (cJSON_IsNumber(field))
                    ESP_LOGI(TAG, "  - %s (number): %d", field->string, field->valueint);
                else if (cJSON_IsBool(field))
                    ESP_LOGI(TAG, "  - %s (bool): %s", field->string, cJSON_IsTrue(field) ? "true" : "false");
                else
                    ESP_LOGI(TAG, "  - %s (other)", field->string);
            }
        }
    }

    /* Extract self-node info */
    parse_self_node_from_map(ml, map_json);

    /* Parse peers */
    parse_peers_from_map_response(ml, map_json);
    ml_filter_update_from_map(map_json);
    ml_wg_mgr_wake(ml);

    /* Extract DERPMap if present — parse all regions and nodes */
    parse_derp_map_from_map(ml, map_json);

    cJSON_Delete(map_json);
    free(resp_buf);

    int64_t t_map_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] MapResponse recv+parse: %ld ms (total map: %ld ms, %dKB)",
             (long)((t_map_done - t_map_sent) / 1000),
             (long)((t_map_done - t_map_start) / 1000),
             (int)(h2_total / 1024));

    return 0;
}

/* ============================================================================
 * State: LONG_POLL - Start streaming MapRequest + process incremental updates
 * ========================================================================== */

/* Send MapRequest with Stream=true to start long-poll on H2 stream 5.
 * omit_peers=false is for streaming_map_fetch: when the initial peer fetch
 * is not done via Stream=false, the first stream message must carry the
 * full netmap (Peers + DERPMap), so OmitPeers is dropped. */
static void lp_reset(microlink_t *ml);
static int do_start_long_poll(microlink_t *ml, ml_noise_state_t *noise, bool omit_peers) {
    lp_reset(ml);   /* fresh stream: drop any partial frames/messages */
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "Version", ML_CTRL_PROTOCOL_VER);

    char key_hex[65], key_str[80];
    bytes_to_hex(ml->wg_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "nodekey:%s", key_hex);
    cJSON_AddStringToObject(root, "NodeKey", key_str);

    bytes_to_hex(ml->disco_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "discokey:%s", key_hex);
    cJSON_AddStringToObject(root, "DiscoKey", key_str);

    /* Hostinfo - REQUIRED by control plane even for Stream=true.
     * V1 includes this; without it, server may not keep us "online". */
    add_hostinfo(ml, root);

    /* Stream=true for long-poll, KeepAlive=true so server sends keepalives
     * (which marks us as "online" on the control plane) */
    cJSON_AddBoolToObject(root, "Stream", true);
    cJSON_AddBoolToObject(root, "KeepAlive", true);
    cJSON_AddStringToObject(root, "Compress", "");    /* Disable compression */
    /* omit_peers=true: peers were already fetched via Stream=false
     * (existing path).
     * omit_peers=false: streaming_map_fetch — receive all peers + DERPMap
     * in the first stream message. */
    cJSON_AddBoolToObject(root, "OmitPeers", omit_peers);

    /* NOTE: With Version >= 68, the control plane IGNORES Endpoints and
     * Hostinfo in Stream=true MapRequests. Endpoints are sent via separate
     * do_send_endpoint_update() calls (Stream=false, OmitPeers=true). */

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return -1;

    size_t json_len = strlen(json_str);
    ESP_LOGI(TAG, "MapRequest: %d bytes (Stream=true)", (int)json_len);

    /* Build H2 frames on stream ID 5 */
    uint8_t *h2_buf = ml_psram_malloc(json_len + 512);
    if (!h2_buf) { free(json_str); return -1; }

    int h2_pos = 0;
    int hdr_len = ml_h2_build_headers_frame(h2_buf, json_len + 512,
                                              "POST", "/machine/map",
                                              CTRL_HOST(ml), "application/json",
                                              5, false);
    if (hdr_len < 0) { free(json_str); free(h2_buf); return -1; }
    h2_pos += hdr_len;

    int data_len = ml_h2_build_data_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                            (uint8_t *)json_str, json_len,
                                            5, true);
    free(json_str);
    if (data_len < 0) { free(h2_buf); return -1; }
    h2_pos += data_len;

    if (noise_send(ml, noise, h2_buf, h2_pos) < 0) {
        free(h2_buf);
        return -1;
    }
    free(h2_buf);

    ESP_LOGI(TAG, "Streaming MapRequest sent on stream 5");
    return 0;
}

/* ----------------------------------------------------------------------------
 * Long-poll stream reassembly
 *
 * The long-poll MapResponse stream is: Noise transport frames -> HTTP/2
 * frames -> stream-5 DATA payload -> length-prefixed messages (4-byte
 * little-endian length + JSON). None of these boundaries line up: an H2
 * frame can span Noise frames and a MapResponse can span many DATA frames.
 * The previous reader handled one Noise frame at a time and kept only the
 * last DATA frame, so anything larger than a single frame was silently
 * dropped (or worse, misparsed) while the device still reported CONNECTED.
 * Owned by the coord task only.
 * -------------------------------------------------------------------------- */
/* HTTP/2's default SETTINGS_MAX_FRAME_SIZE. The H2 preface never raises
 * it, so a server must not send a larger frame (RFC 7540 4.2); a larger
 * length means the stream is misaligned, not a big frame to buffer. */
#define LP_H2_MAX_FRAME  16384u

/* The reassembly state lives in ml->coord_st.lp (one per instance). */
static void lp_reset(microlink_t *ml) {
    free(ml->coord_st.lp.h2);
    free(ml->coord_st.lp.msg);
    memset(&ml->coord_st.lp, 0, sizeof(ml->coord_st.lp));
}

/* Grow *buf to hold at least need bytes: doubling from 8 KB, but never past
 * limit (limit >= need) so the last step doesn't overshoot to twice that. */
static bool lp_reserve(uint8_t **buf, size_t *cap, size_t need, size_t limit) {
    if (need <= *cap && *buf) return true;
    size_t ncap = *cap ? *cap : 8192;
    while (ncap < need) ncap *= 2;
    if (ncap > limit && need <= limit) ncap = limit;
    uint8_t *nb = ml_psram_malloc(ncap);
    if (!nb) return false;
    if (*buf) {
        memcpy(nb, *buf, *cap);
        free(*buf);
    }
    *buf = nb;
    *cap = ncap;
    return true;
}

static void log_map_health(cJSON *root) {
    cJSON *health = cJSON_GetObjectItem(root, "Health");
    if (health && cJSON_IsArray(health)) {
        cJSON *h;
        cJSON_ArrayForEach(h, health) {
            if (cJSON_IsString(h) && h->valuestring && *h->valuestring) {
                ESP_LOGW(TAG, "Control plane health: %s", h->valuestring);
            }
        }
    }
}

static void lp_handle_message(microlink_t *ml, const char *json, size_t len) {
    cJSON *update_json = cJSON_ParseWithLength(json, len);
    if (!update_json) {
        ESP_LOGW(TAG, "Long-poll message: JSON parse failed (%u bytes)", (unsigned)len);
        return;
    }
    ESP_LOGD(TAG, "Long-poll MapResponse update (%u bytes)", (unsigned)len);
    log_map_health(update_json);

    /* Update VPN IP if present */
    cJSON *node = cJSON_GetObjectItem(update_json, "Node");
    if (node) {
        cJSON *addresses = cJSON_GetObjectItem(node, "Addresses");
        if (addresses && addresses_ip6(addresses, ml->vpn_ip6)) ml->has_vpn_ip6 = true;
        if (addresses && cJSON_GetArraySize(addresses) > 0) {
            const char *addr = cJSON_GetArrayItem(addresses, 0)->valuestring;
            if (addr) {
                unsigned a, b, c, d;
                if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                    uint32_t new_ip = (a << 24) | (b << 16) | (c << 8) | d;
                    if (new_ip != ml->vpn_ip) {
                        ml->vpn_ip = new_ip;
                        ESP_LOGI(TAG, "VPN IP updated via long-poll");
                    }
                }
            }
        }
    }

    parse_peers_from_map_response(ml, update_json);
    ml_filter_update_from_map(update_json);
    ml_wg_mgr_wake(ml);

    /* With streaming_map_fetch, DERPMap updates also arrive on this stream. */
    if (ml->config.streaming_map_fetch) {
        parse_derp_map_from_map(ml, update_json);
    }
    cJSON_Delete(update_json);
}

/* Read one Noise frame and append its plaintext to ml->coord_st.lp.h2.
 * Returns 1, 0 when there is no data yet (nothing consumed), or -1 on a
 * hard error (the long-poll state has been reset). */
static int lp_read_frame(microlink_t *ml, ml_noise_state_t *noise) {
    /* Read the Noise header first and reserve exactly what this frame
     * needs (Go servers write frames of at most 4 KB). A fixed 64 KB
     * headroom turned into a 128 KB contiguous block as soon as a partial
     * H2 frame was buffered, which boards without PSRAM can't provide. */
    int ct_len = noise_recv_header(ml);
    if (ct_len < 0) {
        /* EAGAIN/EWOULDBLOCK with nothing consumed = no data yet = not an error */
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        lp_reset(ml);
        return -1;
    }
    size_t pt_len = (size_t)ct_len - 16;
    if (!lp_reserve(&ml->coord_st.lp.h2, &ml->coord_st.lp.h2_cap, ml->coord_st.lp.h2_len + pt_len, SIZE_MAX)) {
        ESP_LOGE(TAG, "Long-poll: out of memory for H2 buffer");
        lp_reset(ml);
        return -1;
    }
    /* Decrypt the frame straight onto the end of the H2 buffer. The header
     * is consumed, so any failure from here on is a hard error. */
    int frame_len = noise_recv_payload(ml, noise, (uint16_t)ct_len, ml->coord_st.lp.h2 + ml->coord_st.lp.h2_len);
    if (frame_len <= 0) {
        lp_reset(ml);
        return -1;  /* error, or an empty frame (as before) */
    }
    ml->coord_st.lp.h2_len += (size_t)frame_len;
    return 1;
}

typedef struct {
    uint32_t data_bytes;    /* DATA payload consumed, all streams (flow control) */
    bool stream5_heard;     /* DATA on stream 5 */
    bool stream5_closed;    /* END_STREAM/RST_STREAM on 5, or GOAWAY */
} lp_h2_result_t;

/* Consume every COMPLETE H2 frame in ml->coord_st.lp.h2 and keep a trailing partial
 * one. Stream-5 DATA is appended to ml->coord_st.lp.msg; PING and SETTINGS are
 * answered. Returns 0, or -1 on a protocol/size error (state reset). */
static int lp_consume_h2(microlink_t *ml, ml_noise_state_t *noise, lp_h2_result_t *r) {
    size_t pos = 0;
    while (pos + 9 <= ml->coord_st.lp.h2_len) {
        const uint8_t *fh = ml->coord_st.lp.h2 + pos;
        uint32_t f_len = ((uint32_t)fh[0] << 16) | ((uint32_t)fh[1] << 8) | fh[2];
        uint8_t f_type = fh[3];
        uint8_t f_flags = fh[4];
        uint32_t f_stream = ((uint32_t)(fh[5] & 0x7F) << 24) | ((uint32_t)fh[6] << 16) |
                            ((uint32_t)fh[7] << 8) | fh[8];
        if (f_len > LP_H2_MAX_FRAME) {
            ESP_LOGE(TAG, "Long-poll: H2 frame length %lu over the %u limit; reconnecting",
                     (unsigned long)f_len, (unsigned)LP_H2_MAX_FRAME);
            lp_reset(ml);
            return -1;
        }
        if (pos + 9 + f_len > ml->coord_st.lp.h2_len) break;  /* partial frame: wait for more */
        const uint8_t *payload = fh + 9;

        if (f_type == 0x00) {  /* DATA */
            r->data_bytes += f_len;
            if (f_stream == 5) {
                r->stream5_heard = true;
                if (f_len > 0) {
                    size_t need = ml->coord_st.lp.msg_len + f_len + 1;
                    if (need > (size_t)ML_JSON_BUFFER_SIZE ||
                        !lp_reserve(&ml->coord_st.lp.msg, &ml->coord_st.lp.msg_cap, need,
                                    (size_t)ML_JSON_BUFFER_SIZE)) {
                        ESP_LOGE(TAG, "Long-poll message exceeds %u KB buffer; reconnecting",
                                 (unsigned)(ML_JSON_BUFFER_SIZE / 1024));
                        lp_reset(ml);
                        return -1;
                    }
                    memcpy(ml->coord_st.lp.msg + ml->coord_st.lp.msg_len, payload, f_len);
                    ml->coord_st.lp.msg_len += f_len;
                }
                if (f_flags & 0x01) {
                    ESP_LOGW(TAG, "Long-poll stream ended by server (END_STREAM)");
                    r->stream5_closed = true;
                }
            } else if (f_len > 0) {
                ESP_LOGD(TAG, "H2 stream %lu DATA: %lu bytes (discarded)",
                         (unsigned long)f_stream, (unsigned long)f_len);
            }
        } else if (f_type == 0x01 && f_stream == 5 && (f_flags & 0x01)) {
            /* HEADERS with END_STREAM on 5: a response without a body (an
             * error status) or trailers. Either way the stream is over. */
            ESP_LOGW(TAG, "Long-poll stream ended by server (HEADERS END_STREAM)");
            r->stream5_closed = true;
        } else if (f_type == 0x06 && f_len == 8 && !(f_flags & 0x01)) {
            /* PING from server: answer with PONG (same payload, ACK flag) */
            uint8_t pong[17] = {0x00, 0x00, 0x08, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00};
            memcpy(pong + 9, payload, 8);
            noise_send(ml, noise, pong, sizeof(pong));
            ESP_LOGD(TAG, "Sent HTTP/2 PONG in response to server PING");
        } else if (f_type == 0x04 && !(f_flags & 0x01)) {
            /* SETTINGS from server: ACK */
            uint8_t settings_ack[9] = {0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00};
            noise_send(ml, noise, settings_ack, sizeof(settings_ack));
        } else if (f_type == 0x03) {
            /* RST_STREAM. Node.Online tracks whether the long-poll stream (5)
             * is open server-side, so a reset of stream 5 means we're about to
             * be shown offline even though the connection still works. */
            uint32_t err_code = f_len >= 4
                ? ((uint32_t)payload[0] << 24 | (uint32_t)payload[1] << 16 |
                   (uint32_t)payload[2] << 8 | payload[3])
                : 0;
            ESP_LOGW(TAG, "H2 RST_STREAM on stream %lu (error %lu)",
                     (unsigned long)f_stream, (unsigned long)err_code);
            if (f_stream == 5) {
                r->stream5_closed = true;
            }
        } else if (f_type == 0x07) {
            ESP_LOGW(TAG, "H2 GOAWAY received - server closing the connection");
            r->stream5_closed = true;
        }
        pos += 9 + f_len;
    }
    if (pos > 0) {
        memmove(ml->coord_st.lp.h2, ml->coord_st.lp.h2 + pos, ml->coord_st.lp.h2_len - pos);
        ml->coord_st.lp.h2_len -= pos;
    }
    return 0;
}

/* Handle every complete length-prefixed MapResponse message in ml->coord_st.lp.msg and
 * keep a trailing partial one. Returns 0, or -1 on a bad length (state reset). */
static int lp_drain_messages(microlink_t *ml) {
    size_t mpos = 0;
    while (ml->coord_st.lp.msg_len - mpos >= 4) {
        const uint8_t *m = ml->coord_st.lp.msg + mpos;
        uint32_t mlen = (uint32_t)m[0] | ((uint32_t)m[1] << 8) |
                        ((uint32_t)m[2] << 16) | ((uint32_t)m[3] << 24);
        if (mlen > (uint32_t)ML_JSON_BUFFER_SIZE) {
            ESP_LOGE(TAG, "Long-poll message length %lu invalid; reconnecting", (unsigned long)mlen);
            lp_reset(ml);
            return -1;
        }
        if (ml->coord_st.lp.msg_len - mpos - 4 < mlen) break;  /* incomplete message */
        if (mlen > 0) {
            lp_handle_message(ml, (const char *)(m + 4), mlen);
        }
        mpos += 4 + mlen;
    }
    if (mpos > 0) {
        memmove(ml->coord_st.lp.msg, ml->coord_st.lp.msg + mpos, ml->coord_st.lp.msg_len - mpos);
        ml->coord_st.lp.msg_len -= mpos;
    }
    return 0;
}

static void lp_send_window_update(microlink_t *ml, ml_noise_state_t *noise,
                                  uint32_t bytes, bool stream5) {
    if (bytes == 0) return;
    uint8_t wu_buf[26];  /* 2 WINDOW_UPDATE frames: 13 bytes each */
    int wu_len = ml_h2_build_window_update(wu_buf, 13, 0, bytes);
    if (stream5) {
        wu_len += ml_h2_build_window_update(wu_buf + wu_len, 13, 5, bytes);
    }
    if (wu_len > 0) noise_send(ml, noise, wu_buf, wu_len);
}

/* For streaming_map_fetch: blockingly read the first MapResponse (the full
 * netmap) on stream 5 opened by do_start_long_poll(omit_peers=false), and
 * parse Node / Peers / DERPMap from it.
 *
 * headscale-based controllers such as ZTL do not respond to Stream=false
 * MapRequests, so this function fetches the initial netmap instead of
 * do_fetch_peers. A Stream=true response keeps the stream open and never
 * sends END_STREAM, so do_fetch_peers' END_STREAM detection cannot be used.
 * Instead, message completion is detected via the 4-byte length prefix at
 * the start of each message (the Tailscale/headscale map stream framing).
 *
 * The netmap is reassembled in the long-poll buffers (ml->coord_st.lp, reset by
 * do_start_long_poll), so whatever the server wrote right behind it - a
 * PeersRemoved / PeersChangedPatch / DERPMap delta, or the first part of
 * one - is not dropped: complete messages are handled right after the
 * netmap and partial ones stay queued for poll_map_update().
 *
 * The DERP connect request must be issued only after this function
 * succeeds — in the reverse order we would try to connect to DERP without
 * a DERPMap and fail (same symptom as getting stuck with Stream=false). */
static int do_read_initial_netmap(microlink_t *ml, ml_noise_state_t *noise) {
    int64_t t_map_start = esp_timer_get_time();

    /* The initial netmap can be large, so wait up to 60 seconds (same as do_fetch_peers) */
    coord_set_rcv_timeout(ml, 60000);

    uint64_t recv_start_ms = ml_get_time_ms();
    uint64_t last_progress_ms = recv_start_ms;
    uint32_t window_consumed = 0;

    size_t msg_len = 0;           /* Body length from the length prefix (0 = not yet known) */
    size_t msg_off = 0;           /* Body start offset (= prefix length) */
    bool msg_complete = false;
    bool stream_closed = false;

    for (int read_count = 0; read_count < 200 && !msg_complete && !stream_closed; read_count++) {
        if (lp_read_frame(ml, noise) <= 0) break;  /* timeout, or error (state reset) */

        /* Consume only complete H2 frames, in order. An H2 frame can span
         * multiple Noise frames; a partial one stays in ml->coord_st.lp.h2. */
        lp_h2_result_t h2 = {0};
        if (lp_consume_h2(ml, noise, &h2) < 0) break;
        window_consumed += h2.data_bytes;
        stream_closed = h2.stream5_closed;

        /* Message completion check: 4-byte length prefix at the start.
         * Tailscale / headscale write it little-endian, but as a safeguard
         * against implementation differences, try BE if the LE value is
         * implausible; raw JSON without a prefix (starting with '{') is
         * considered complete once it parses fully. */
        const uint8_t *mb = ml->coord_st.lp.msg;
        size_t have = ml->coord_st.lp.msg_len;
        if (msg_len == 0 && have >= 5) {
            size_t plen = 0;
            if (map_json_offset(mb, have, &plen) == 4) {
                msg_len = plen;
                msg_off = 4;
            }
        }
        if (msg_len > 0 && have >= msg_off + msg_len) {
            msg_complete = true;
            ESP_LOGI(TAG, "Initial netmap complete: %d bytes (%lums)",
                     (int)msg_len, (unsigned long)(ml_get_time_ms() - recv_start_ms));
        } else if (msg_len == 0 && have > 0 && mb[0] == '{') {
            cJSON *probe = cJSON_ParseWithLength((const char *)mb, have);
            if (probe) {
                cJSON_Delete(probe);
                msg_len = have;
                msg_off = 0;
                msg_complete = true;
                ESP_LOGI(TAG, "Initial netmap complete (no length prefix): %d bytes",
                         (int)msg_len);
            }
        }

        uint64_t now = ml_get_time_ms();
        if (!msg_complete && now - last_progress_ms > 5000) {
            ESP_LOGI(TAG, "Initial netmap: %d of %d bytes so far (%lums elapsed)",
                     (int)have, (int)(msg_off + msg_len), (unsigned long)(now - recv_start_ms));
            last_progress_ms = now;
        }

        /* Every 32KB, replenish flow control with WINDOW_UPDATE (connection
         * level + stream 5) so the server never stalls sending (same
         * pattern as do_fetch_peers). */
        if (window_consumed >= 32768) {
            lp_send_window_update(ml, noise, window_consumed, true);
            window_consumed = 0;
        }
    }

    /* Restore the normal recv timeout (5 seconds) */
    coord_set_rcv_timeout(ml, 5000);

    /* Replenish the remaining flow control. Stream 5 stays open (the
     * long-poll continues), so always replenish the stream level as well,
     * not just the connection level. */
    lp_send_window_update(ml, noise, window_consumed, true);

    if (!msg_complete) {
        ESP_LOGW(TAG, "Initial netmap not received (got %d bytes, stream %s)",
                 (int)ml->coord_st.lp.msg_len, stream_closed ? "closed" : "open");
        lp_reset(ml);
        return -1;
    }

    /* Parse the body (skipping the prefix), cut at msg_len. */
    cJSON *map_json = cJSON_ParseWithLength((const char *)ml->coord_st.lp.msg + msg_off, msg_len);
    if (!map_json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "Initial netmap JSON parse failed near: %.50s", err ? err : "unknown");
        lp_reset(ml);
        return -1;
    }

    /* Hand whatever follows the netmap to the long-poll reassembler. */
    size_t used = msg_off + msg_len;
    memmove(ml->coord_st.lp.msg, ml->coord_st.lp.msg + used, ml->coord_st.lp.msg_len - used);
    ml->coord_st.lp.msg_len -= used;
    /* The buffer grew to the netmap size; long-poll deltas are small, so
     * don't hold that block for the whole session. lp_reserve() grows it
     * again if a large delta arrives. */
    if (ml->coord_st.lp.msg_cap > 8192 && ml->coord_st.lp.msg_len < 8192) {
        uint8_t *nb = ml_psram_malloc(8192);
        if (nb) {
            memcpy(nb, ml->coord_st.lp.msg, ml->coord_st.lp.msg_len);
            free(ml->coord_st.lp.msg);
            ml->coord_st.lp.msg = nb;
            ml->coord_st.lp.msg_cap = 8192;
        }
    }
    if (ml->coord_st.lp.msg_len > 0 || ml->coord_st.lp.h2_len > 0) {
        ESP_LOGI(TAG, "Initial netmap: %u message + %u H2 bytes after it kept for the long-poll",
                 (unsigned)ml->coord_st.lp.msg_len, (unsigned)ml->coord_st.lp.h2_len);
    }

    /* Ingest self-node info / peers / DERPMap (via the same shared parsers
     * as do_fetch_peers — the DERP connection relies on the DERPMap being
     * reliably parsed here). */
    log_map_health(map_json);
    parse_self_node_from_map(ml, map_json);
    parse_peers_from_map_response(ml, map_json);
    ml_filter_update_from_map(map_json);
    ml_wg_mgr_wake(ml);
    parse_derp_map_from_map(ml, map_json);
    cJSON_Delete(map_json);

    /* Updates that arrived complete behind the netmap apply on top of it. */
    if (lp_drain_messages(ml) < 0) return -1;

    if (stream_closed) {
        /* The netmap is applied, but this stream can't carry updates. */
        ESP_LOGW(TAG, "Map stream closed by the server after the initial netmap");
        lp_reset(ml);
        return -1;
    }

    int64_t t_map_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] Initial netmap recv+parse: %ld ms (%dKB)",
             (long)((t_map_done - t_map_start) / 1000), (int)(msg_len / 1024));

    return 0;
}

/* Send a "lite" endpoint update to the control plane.
 * This is a non-streaming MapRequest (Stream=false, OmitPeers=true) that
 * only updates our endpoints and hostinfo. Required because Version >= 68
 * means the control plane IGNORES Endpoints in streaming (Stream=true)
 * MapRequests. The reference client uses a dedicated "updateRoutine" for this.
 *
 * Uses H2 stream 7. Response body is discarded (only HTTP status matters).
 * Returns 0 on success, -1 on send failure. */
static int do_send_endpoint_update(microlink_t *ml, ml_noise_state_t *noise) {
    if (ml->stun_public_ip == 0 && !ml->stun_has_ipv6) {
        ESP_LOGD(TAG, "No STUN endpoints yet, skipping endpoint update");
        return 0;  /* Nothing to send */
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "Version", ML_CTRL_PROTOCOL_VER);

    char key_hex[65], key_str[80];
    bytes_to_hex(ml->wg_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "nodekey:%s", key_hex);
    cJSON_AddStringToObject(root, "NodeKey", key_str);

    bytes_to_hex(ml->disco_public_key, 32, key_hex);
    snprintf(key_str, sizeof(key_str), "discokey:%s", key_hex);
    cJSON_AddStringToObject(root, "DiscoKey", key_str);

    /* Stream=false so control plane PROCESSES our endpoints (Version >= 68) */
    cJSON_AddBoolToObject(root, "Stream", false);
    cJSON_AddBoolToObject(root, "KeepAlive", true);
    /* OmitPeers=true — we don't need peers back, just updating our endpoints */
    cJSON_AddBoolToObject(root, "OmitPeers", true);
    cJSON_AddStringToObject(root, "Compress", "");

    /* Hostinfo (required — control plane reads NetInfo from here) */
    add_hostinfo(ml, root);

    /* Endpoints + EndpointTypes */
    int ep_count = add_endpoints_to_json(ml, root);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return -1;

    size_t json_len = strlen(json_str);
    ESP_LOGI(TAG, "Endpoint update: %d bytes, %d endpoints (Stream=false, OmitPeers=true)",
             (int)json_len, ep_count);

    /* Use incrementing odd stream IDs (H2 client-initiated = odd).
     * Streams 1, 3, 5 are used by register, fetch peers, and long-poll.
     * Start at 7, increment by 2 for each endpoint update.
     * Reset to 7 on reconnect (h2_next_stream_id initialized in connect). */
    if (ml->h2_next_stream_id < 7) ml->h2_next_stream_id = 7;
    uint32_t sid = ml->h2_next_stream_id;
    ml->h2_next_stream_id += 2;

    uint8_t *h2_buf = ml_psram_malloc(json_len + 512);
    if (!h2_buf) { free(json_str); return -1; }

    int h2_pos = 0;
    int hdr_len = ml_h2_build_headers_frame(h2_buf, json_len + 512,
                                              "POST", "/machine/map",
                                              CTRL_HOST(ml), "application/json",
                                              sid, false);
    if (hdr_len < 0) { free(json_str); free(h2_buf); return -1; }
    h2_pos += hdr_len;

    int data_len = ml_h2_build_data_frame(h2_buf + h2_pos, json_len + 512 - h2_pos,
                                            (uint8_t *)json_str, json_len,
                                            sid, true);  /* END_STREAM */
    free(json_str);
    if (data_len < 0) { free(h2_buf); return -1; }
    h2_pos += data_len;

    if (noise_send(ml, noise, h2_buf, h2_pos) < 0) {
        free(h2_buf);
        ESP_LOGE(TAG, "Failed to send endpoint update");
        return -1;
    }
    free(h2_buf);

    ESP_LOGD(TAG, "Endpoint update sent on H2 stream %lu", (unsigned long)sid);
    /* Response body is discarded — server may send empty response or
     * we'll consume it in the next poll_map_update() iteration.
     * Only the HTTP status code matters (200 = success). */
    return 0;
}

static int poll_map_update(microlink_t *ml, ml_noise_state_t *noise) {
#ifdef CONFIG_ML_CTRL_TLS
    /* Decrypted bytes may already sit in the TLS layer with nothing left
     * on the socket — select() alone would miss them. */
    if (ml_coord_tls_pending(ml) == 0)
#endif
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(ml->coord_sock, &readfds);
        /* Data wakes select() at once; the timeout only paces the loop's
         * periodic work (PINGs every 5 s, STUN, watchdog) and stop checks. */
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
        int sel = ml_select_fds(ml->coord_sock + 1, &readfds, NULL, NULL, &tv);
        if (sel <= 0) return 0;  /* No data available or error */
    }

    /* Data available — set short recv timeout for partial frame safety */
    coord_set_rcv_timeout(ml, 2000);

    int rf = lp_read_frame(ml, noise);
    if (rf <= 0) return rf;  /* 0 = no data yet, -1 = error / connection closed */

    lp_h2_result_t h2 = {0};
    if (lp_consume_h2(ml, noise, &h2) < 0) return -1;

    /* Replenish HTTP/2 flow control (connection + stream level). */
    lp_send_window_update(ml, noise, h2.data_bytes, h2.stream5_heard);

    /* Extract complete length-prefixed MapResponse messages. */
    if (lp_drain_messages(ml) < 0) return -1;

    if (h2.stream5_closed) {
        /* Reconnect now rather than waiting for the watchdog. */
        lp_reset(ml);
        return -1;
    }

    /* Only traffic on stream 5 (what the server's Node.Online tracks) proves
     * the long-poll is alive; PING ACKs etc. on stream 0 don't reset the
     * caller's watchdog. */
    return h2.stream5_heard ? 1 : 0;
}

/* ============================================================================
 * Coordination Task Main Loop
 * ========================================================================== */

void ml_coord_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "Coord task started (Core %d)", xPortGetCoreID());

    coord_state_t state = COORD_IDLE;
    ml_coord_cmd_t cmd;
    uint64_t last_activity_ms = ml_get_time_ms();
    int reconnect_attempts = 0;

    /* Noise protocol state - owned exclusively by this task */
    ml_noise_state_t noise = {0};

    /* Wait for WiFi/cellular OR shutdown */
    ESP_LOGI(TAG, "Waiting for the network...");
    {
        EventBits_t wb = xEventGroupWaitBits(ml->events,
                             ML_EVT_WIFI_CONNECTED | ML_EVT_SHUTDOWN_REQUEST,
                             pdFALSE, pdFALSE, portMAX_DELAY);
        if (wb & ML_EVT_SHUTDOWN_REQUEST) {
            ESP_LOGI(TAG, "Shutdown requested before WiFi, exiting");
            ml_task_exit(ml, ML_TASK_BIT_COORD);
        }
    }

    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {
        /* Check for commands (non-blocking) */
        if (xQueueReceive(ml->coord_cmd_queue, &cmd, 0) == pdTRUE) {
            switch (cmd) {
            case ML_CMD_CONNECT:
                if (state == COORD_IDLE) {
                    state = COORD_STUN_PROBE;
                    ml->state = ML_STATE_CONNECTING;
                }
                break;
            case ML_CMD_DISCONNECT:
                coord_close_conn(ml);
                state = COORD_IDLE;
                ml->state = ML_STATE_IDLE;
                break;
            case ML_CMD_FORCE_RECONNECT:
                state = COORD_RECONNECTING;
                break;
            case ML_CMD_UPDATE_ENDPOINTS:
                /* TODO: Send endpoint update on existing H2 connection */
                break;
            }
        }

        /* DERP reconnect is now handled by the DERP I/O task itself.
         * The I/O task checks ML_EVT_DERP_RECONNECT directly. */

        switch (state) {
        case COORD_IDLE:
            vTaskDelay(pdMS_TO_TICKS(100));
            break;

        case COORD_STUN_PROBE:
            ESP_LOGI(TAG, "Running STUN probe...");
            /* Pre-resolve STUN servers (cached, only resolves once) */
            ml_stun_resolve_servers(ml);
            /* Reset retry state for fresh probe sequence */
            ml->stun_retry_count = 1;  /* First probe counts as attempt 1 */
            ml->stun_using_fallback = false;
            ml->stun_last_probe_ms = ml_get_time_ms();
            /* Send first probe to Tailscale STUN primary (IPv4) */
            if (ml->stun_primary_ip) {
                ml_stun_send_probe_to(ml, ml->stun_primary_ip, ML_STUN_PRIMARY_PORT);
            } else if (ml->stun_fallback_ip) {
                ml->stun_using_fallback = true;
                ml_stun_send_probe_to(ml, ml->stun_fallback_ip, ML_STUN_FALLBACK_PORT);
            } else {
                /* Both DNS failed, try hostname-based as last resort */
                ml_stun_send_probe(ml, ML_STUN_PRIMARY_HOST, ML_STUN_PRIMARY_PORT);
            }
            /* Also send IPv6 STUN probe if resolved */
            {
                static const uint8_t zero16[16] = {0};
                if (memcmp(ml->stun_primary_ip6, zero16, 16) != 0) {
                    ml_stun_send_probe_ipv6(ml, ml->stun_primary_ip6, ML_STUN_PRIMARY_PORT);
                }
            }
            state = COORD_DNS_RESOLVE;
            break;

        case COORD_DNS_RESOLVE:
        case COORD_TCP_CONNECT:
            if (do_tcp_connect(ml) < 0) {
                ESP_LOGE(TAG, "TCP connect failed, retrying...");
                state = COORD_RECONNECTING;
                break;
            }
            ml->h2_next_stream_id = 7;  /* Reset H2 stream counter for new connection */
            state = COORD_NOISE_HANDSHAKE;
            break;

        case COORD_NOISE_HANDSHAKE:
            /* Keep NEEDS_LOGIN visible while the Followup is repeated */
            if (ml->state != ML_STATE_NEEDS_LOGIN) ml->state = ML_STATE_REGISTERING;
            if (do_noise_handshake(ml, &noise) < 0) {
                ESP_LOGE(TAG, "Noise handshake failed");
                coord_close_conn(ml);
                state = COORD_RECONNECTING;
                break;
            }
            /* Process proactive server frames (EarlyNoise, H2 SETTINGS)
             * before sending our H2 preface. Extracts nodeKeyChallenge
             * and adjusts rx_nonce. */
            process_proactive_frames(ml, &noise);
            state = COORD_H2_PREFACE;
            break;

        case COORD_H2_PREFACE:
            if (do_h2_preface(ml, &noise) < 0) {
                ESP_LOGE(TAG, "H2 preface failed");
                coord_close_conn(ml);
                state = COORD_RECONNECTING;
                break;
            }
            state = COORD_REGISTER;
            break;

        case COORD_REGISTER:
            ESP_LOGI(TAG, "Registering...");
            {
                uint64_t reg_start_ms = ml_get_time_ms();
                int reg_rc = do_register(ml, &noise);
                if (reg_rc == ML_REG_NEEDS_LOGIN || reg_rc == ML_REG_PENDING) {
                    /* Reconnect at once and send the Followup (register uses
                     * stream 1 of a fresh connection). */
                    if (reg_rc == ML_REG_NEEDS_LOGIN) {
                        ESP_LOGW(TAG, "Login required: open the URL from "
                                      "microlink_get_auth_url() to add this device");
                        ESP_LOGD(TAG, "Login URL: %s", ml->auth_url);
                        ml->state = ML_STATE_NEEDS_LOGIN;
                        if (ml->state_cb) {
                            ml->state_cb(ml, ML_STATE_NEEDS_LOGIN, ml->state_cb_data);
                        }
                    }
                    /* Retry at once after a new URL or a Followup the server
                     * held open (a real wait for the user). One it answered
                     * straight away (e.g. waiting for device approval) backs
                     * off like any other retry instead of looping every 1 s. */
                    if (reg_rc == ML_REG_NEEDS_LOGIN ||
                        ml_get_time_ms() - reg_start_ms >= 10000) {
                        reconnect_attempts = 0;
                    }
                    coord_close_conn(ml);
                    state = COORD_RECONNECTING;
                    break;
                }
                if (reg_rc < 0) {
                    ESP_LOGE(TAG, "Registration failed");
                    if (reg_rc == ML_REG_AUTH_FAILED) {
                        /* Not transient: retrying with the same key will keep
                         * failing. Notify the host (its "re-login" prompt) and
                         * jump to maximum backoff — the loop keeps running in
                         * case the key is re-enabled server-side. */
                        ml->state = ML_STATE_AUTH_FAILED;
                        if (ml->state_cb) {
                            ml->state_cb(ml, ML_STATE_AUTH_FAILED, ml->state_cb_data);
                        }
                        reconnect_attempts = 5;
                    }
                    coord_close_conn(ml);
                    state = COORD_RECONNECTING;
                    break;
                }
            }
            state = COORD_FETCH_PEERS;
            break;

        case COORD_FETCH_PEERS:
            ESP_LOGI(TAG, "Fetching peers...");
            if (ml->config.streaming_map_fetch) {
                /* headscale-based controllers such as ZTL do not respond to
                 * Stream=false MapRequests (60s of zero bytes -> Empty
                 * MapResponse -> reconnect loop). Like the official client,
                 * start a single Stream=true / OmitPeers=false stream from
                 * the beginning and take the full netmap (Peers + DERPMap)
                 * from the first stream message. The DERP connect request is
                 * issued after this point, once the DERPMap has been parsed
                 * (in the reverse order we would try to connect to DERP
                 * without a DERPMap and fail). */
                if (do_start_long_poll(ml, &noise, false) < 0 ||
                    do_read_initial_netmap(ml, &noise) < 0) {
                    ESP_LOGW(TAG, "Streaming MapRequest failed, will retry");
                    coord_close_conn(ml);
                    state = COORD_RECONNECTING;
                    break;
                }
            } else {
                int fr = do_fetch_peers(ml, &noise);
                if (fr == -2) {
                    /* Headscale-style servers send no netmap for Stream=false.
                     * Switch to the streaming initial fetch (as the official
                     * client always does) and reconnect right away. */
                    ESP_LOGW(TAG, "Control server sent no netmap for Stream=false; "
                                  "switching to streaming map fetch");
                    ml->config.streaming_map_fetch = true;
                    coord_close_conn(ml);
                    reconnect_attempts = 0;
                    state = COORD_RECONNECTING;
                    break;
                }
                if (fr < 0) {
                    ESP_LOGW(TAG, "MapRequest failed, will retry");
                    coord_close_conn(ml);
                    state = COORD_RECONNECTING;
                    break;
                }
            }

            xEventGroupSetBits(ml->events, ML_EVT_COORD_REGISTERED);

            /* Signal DERP I/O task to connect (connection now owned by I/O task) */
            if (!ml->derp.connected) {
                xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECT_REQ);
                /* Wait for DERP to connect (up to 15s) before continuing */
                ESP_LOGI(TAG, "Waiting for DERP I/O task to connect...");
                xEventGroupWaitBits(ml->events,
                                    ML_EVT_DERP_CONNECTED | ML_EVT_SHUTDOWN_REQUEST,
                                    pdFALSE, pdFALSE, pdMS_TO_TICKS(15000));
            }

            /* Start streaming long-poll for incremental updates.
             * With streaming_map_fetch, the long-poll on stream 5 was
             * already started for the initial fetch, so do not start it a
             * second time (reusing the same stream ID would violate the H2
             * protocol). */
            if (!ml->config.streaming_map_fetch) {
                if (do_start_long_poll(ml, &noise, true) < 0) {
                    ESP_LOGW(TAG, "Failed to start long-poll (non-fatal)");
                }
            }

            /* Send initial endpoint update if STUN already completed.
             * (STUN runs concurrently and may have results by now.) */
            if (ml->stun_public_ip != 0 || ml->stun_has_ipv6) {
                do_send_endpoint_update(ml, &noise);
            }

            /* Send initial HTTP/2 PING immediately to keep connection active
             * before the periodic 5s timer kicks in (server has ~20s idle timeout) */
            {
                uint8_t ping_frame[17];
                ping_frame[0] = 0x00; ping_frame[1] = 0x00; ping_frame[2] = 0x08;
                ping_frame[3] = 0x06; ping_frame[4] = 0x00;
                ping_frame[5] = 0x00; ping_frame[6] = 0x00;
                ping_frame[7] = 0x00; ping_frame[8] = 0x00;
                memset(ping_frame + 9, 0x42, 8);
                noise_send(ml, &noise, ping_frame, sizeof(ping_frame));
                ESP_LOGI(TAG, "Sent initial HTTP/2 PING after long-poll");
            }

            state = COORD_LONG_POLL;
            ml->state = ML_STATE_CONNECTED;
            reconnect_attempts = 0;
            ml_ota_confirm();
            last_activity_ms = ml_get_time_ms();

            /* Notify app */
            if (ml->state_cb) {
                ml->state_cb(ml, ML_STATE_CONNECTED, ml->state_cb_data);
            }
            break;

        case COORD_LONG_POLL:
            {
                uint64_t now = ml_get_time_ms();

                /* Check control plane watchdog (120s) */
                if (now - last_activity_ms > ml->t_ctrl_watchdog_ms) {
                    ESP_LOGW(TAG, "Control plane watchdog timeout");
                    state = COORD_RECONNECTING;
                    break;
                }

                /* Check for STUN response in queue (IPv4 or IPv6) */
                ml_rx_packet_t stun_pkt;
                if (xQueueReceive(ml->stun_rx_queue, &stun_pkt, 0) == pdTRUE) {
                    uint32_t pub_ip;
                    uint16_t pub_port;
                    bool parsed = false;

                    /* Try IPv4 parse first */
                    if (ml_stun_parse_response(stun_pkt.data, stun_pkt.len,
                                                &pub_ip, &pub_port)) {
                        if (ml->stun_public_ip == 0) {
                            /* First STUN result (primary server) */
                            ml->stun_public_ip = pub_ip;
                            ml->stun_public_port = pub_port;
                            ml->stun_retry_count = 0;
                            /* Send probe to fallback for symmetric NAT check */
                            if (!ml->stun_nat_checked && ml->stun_fallback_ip) {
                                ml_stun_send_probe_to(ml, ml->stun_fallback_ip,
                                                       ML_STUN_FALLBACK_PORT);
                                ESP_LOGI(TAG, "Sent STUN to fallback for NAT type detection");
                            }
                        } else if (!ml->stun_nat_checked) {
                            /* Second STUN result (fallback) — compare ports */
                            ml->stun_secondary_port = pub_port;
                            ml->stun_nat_checked = true;
                            if (ml->stun_public_port != pub_port) {
                                ml->nat_mapping_varies = true;
                                ESP_LOGW(TAG, "Symmetric NAT detected: port %u vs %u "
                                         "(direct connections unlikely)",
                                         ml->stun_public_port, pub_port);
                            } else {
                                ml->nat_mapping_varies = false;
                                ESP_LOGI(TAG, "Cone NAT: port %u consistent "
                                         "(direct connections possible)", pub_port);
                            }
                        } else {
                            /* Periodic re-probe — update primary result */
                            ml->stun_public_ip = pub_ip;
                            ml->stun_public_port = pub_port;
                            ml->stun_retry_count = 0;
                        }
                        parsed = true;
                    }

                    /* Try IPv6 parse (response may contain IPv6 XOR-MAPPED-ADDRESS) */
                    if (!parsed) {
                        uint8_t ip6[16];
                        uint16_t port6;
                        if (ml_stun_parse_response_ipv6(stun_pkt.data, stun_pkt.len,
                                                         ip6, &port6)) {
                            memcpy(ml->stun_public_ip6, ip6, 16);
                            ml->stun_public_port6 = port6;
                            ml->stun_has_ipv6 = true;
                            /* Use IPv6 port for NAT detection if no IPv4 result yet */
                            if (ml->stun_public_port == 0) {
                                ml->stun_public_port = port6;
                            }
                            ml->stun_retry_count = 0;  /* Got a result, stop retrying */
                            ESP_LOGD(TAG, "STUN IPv6 result obtained, port %u", port6);
                            /* Trigger NAT type check if not done yet */
                            if (!ml->stun_nat_checked && ml->stun_fallback_ip) {
                                ml_stun_send_probe_to(ml, ml->stun_fallback_ip,
                                                       ML_STUN_FALLBACK_PORT);
                                ESP_LOGI(TAG, "Sent STUN to fallback for NAT type detection");
                            }
                            parsed = true;
                        }
                    }

                    if (parsed) {
                        xEventGroupSetBits(ml->events, ML_EVT_STUN_COMPLETE);
                        /* Send endpoint update to control plane immediately.
                         * With Version >= 68, Stream=true MapRequests have endpoints
                         * IGNORED, so we need this separate Stream=false request. */
                        do_send_endpoint_update(ml, &noise);
                    }
                    free(stun_pkt.data);
                }

                /* STUN retry logic: 3 attempts per server, 2s apart, then fallback */
                if (ml->stun_retry_count > 0 && ml->stun_retry_count <= ML_STUN_MAX_RETRIES) {
                    if (now - ml->stun_last_probe_ms > ML_STUN_RETRY_INTERVAL_MS) {
                        if (!ml->stun_using_fallback && ml->stun_primary_ip) {
                            ml_stun_send_probe_to(ml, ml->stun_primary_ip, ML_STUN_PRIMARY_PORT);
                        } else if (ml->stun_fallback_ip) {
                            ml_stun_send_probe_to(ml, ml->stun_fallback_ip, ML_STUN_FALLBACK_PORT);
                        }
                        ml->stun_last_probe_ms = now;
                        ml->stun_retry_count++;
                        if (ml->stun_retry_count > ML_STUN_MAX_RETRIES && !ml->stun_using_fallback) {
                            /* Primary exhausted, switch to fallback */
                            ESP_LOGW(TAG, "STUN primary failed after %d retries, trying fallback",
                                     ML_STUN_MAX_RETRIES);
                            ml->stun_using_fallback = true;
                            ml->stun_retry_count = 1;
                            if (ml->stun_fallback_ip) {
                                ml_stun_send_probe_to(ml, ml->stun_fallback_ip, ML_STUN_FALLBACK_PORT);
                                ml->stun_last_probe_ms = now;
                            }
                        }
                    }
                }

                /* Periodic STUN re-probe (every 23s) — fresh probe sequence */
                static uint64_t last_stun_ms = 0;
                if (now - last_stun_ms > ml->t_stun_interval_ms) {
                    ml->stun_retry_count = 1;
                    ml->stun_using_fallback = false;
                    ml->stun_last_probe_ms = now;
                    /* IPv4 probe */
                    if (ml->stun_primary_ip) {
                        ml_stun_send_probe_to(ml, ml->stun_primary_ip, ML_STUN_PRIMARY_PORT);
                    } else if (ml->stun_fallback_ip) {
                        ml->stun_using_fallback = true;
                        ml_stun_send_probe_to(ml, ml->stun_fallback_ip, ML_STUN_FALLBACK_PORT);
                    } else {
                        ml_stun_send_probe(ml, ML_STUN_PRIMARY_HOST, ML_STUN_PRIMARY_PORT);
                    }
                    /* IPv6 probe (alongside IPv4) */
                    {
                        static const uint8_t zero16[16] = {0};
                        if (memcmp(ml->stun_primary_ip6, zero16, 16) != 0) {
                            ml_stun_send_probe_ipv6(ml, ml->stun_primary_ip6, ML_STUN_PRIMARY_PORT);
                        }
                    }
                    last_stun_ms = now;
                }

                /* Periodic DERP NotePreferred keepalive (every 60s) */
                static uint64_t last_derp_keepalive_ms = 0;
                if (ml->derp.connected && now - last_derp_keepalive_ms > 60000) {
                    uint8_t preferred = 0x01;
                    uint8_t *ka_data = malloc(1);
                    if (ka_data) {
                        *ka_data = preferred;
                        ml_derp_tx_item_t ka_item = {
                            .data = ka_data,
                            .len = 1,
                            .frame_type = 0x07,  /* NotePreferred */
                        };
                        memset(ka_item.dest_pubkey, 0, 32);
                        if (xQueueSend(ml->derp_tx_queue, &ka_item, 0) != pdTRUE) {
                            free(ka_data);
                        }
                    }
                    last_derp_keepalive_ms = now;
                }

                /* Key expiry check (every 60s) — re-register if expired */
                if (ml->key_expiry_epoch > 0 || ml->key_expired) {
                    static uint64_t last_expiry_check_ms = 0;
                    if (now - last_expiry_check_ms > 60000) {
                        last_expiry_check_ms = now;
                        if (ml->key_expired) {
                            /* With an auth key, register again with it. Without
                             * one (interactive login), register without: the
                             * server answers with a new login URL and the
                             * device goes to NEEDS_LOGIN. */
                            if (ml->config.auth_key && ml->config.auth_key[0]) {
                                ESP_LOGW(TAG, "Key expired, re-registering with auth_key...");
                            } else {
                                ESP_LOGW(TAG, "Key expired, asking for a new login...");
                            }
                            state = COORD_RECONNECTING;
                            break;
                        }
                        /* Warn 1 hour before expiry (rough uptime-based check) */
                        /* Note: key_expiry_epoch is absolute Unix time, we compare with
                         * approximate boot-relative time. For accurate check we'd need
                         * SNTP, but this catches the Expired flag from the server. */
                    }
                }

                /* Send HTTP/2 PING every 5 seconds to keep control plane alive.
                 * The server has a ~20s idle timeout; PINGs maintain bidirectional
                 * activity and are what actually keep us "online". (v1 reference)
                 *
                 * Deliberately does NOT touch last_activity_ms on send success -
                 * see the watchdog comment below. A local send() succeeding only
                 * means the data was handed to this device's own TCP stack, not
                 * that the server ever received or answered it (a real, hardware-
                 * found bug: a silently one-way-dead long-poll connection, e.g.
                 * after a NAT rebind, let this branch "succeed" every 5s forever,
                 * so the 120s watchdog below could never fire even though nothing
                 * had actually come back from the server in hours - confirmed on
                 * real hardware, see esp32/REMOTE_ACCESS.md's 2026-09-01 entry). */
                static uint64_t last_h2_ping_ms = 0;
                if (now - last_h2_ping_ms >= 5000) {
                    uint8_t ping_frame[17];
                    ping_frame[0] = 0x00; ping_frame[1] = 0x00; ping_frame[2] = 0x08;
                    ping_frame[3] = 0x06;  /* Type: PING */
                    ping_frame[4] = 0x00;  /* Flags: none */
                    ping_frame[5] = 0x00; ping_frame[6] = 0x00;
                    ping_frame[7] = 0x00; ping_frame[8] = 0x00;  /* Stream 0 */
                    /* Opaque 8-byte payload (timestamp for identification) */
                    uint64_t ping_id = now;
                    for (int b = 0; b < 8; b++)
                        ping_frame[9 + b] = (ping_id >> (56 - b * 8)) & 0xFF;
                    int ping_ret = noise_send(ml, &noise, ping_frame, sizeof(ping_frame));
                    if (ping_ret >= 0) {
                        last_h2_ping_ms = now;
                    } else {
                        ESP_LOGW(TAG, "H2 PING send failed, reconnecting");
                        state = COORD_RECONNECTING;
                        break;
                    }
                }

                /* Poll for streaming MapResponse updates */
                int poll_ret = poll_map_update(ml, &noise);
                if (poll_ret > 0) {
                    last_activity_ms = now;  /* Reset watchdog */
                } else if (poll_ret < 0) {
                    ESP_LOGW(TAG, "Long-poll connection lost");
                    state = COORD_RECONNECTING;
                    break;
                }

                /* No extra sleep: poll_map_update() already blocked in select() */
            }
            break;

        case COORD_RECONNECTING:
            {
                uint32_t backoff_ms = 1000 << (reconnect_attempts > 4 ? 4 : reconnect_attempts);
                if (backoff_ms > ML_CTRL_BACKOFF_MAX_MS) backoff_ms = ML_CTRL_BACKOFF_MAX_MS;

                ESP_LOGI(TAG, "Reconnecting in %lu ms (attempt %d)",
                         (unsigned long)backoff_ms, reconnect_attempts + 1);

                /* Notify the host like CONNECTED and AUTH_FAILED do, so a
                 * status display does not keep showing "connected" through an
                 * outage. The loop re-enters this state on every backoff
                 * cycle, so fire only on the transition — and never downgrade
                 * AUTH_FAILED, which requires human action: overwriting it
                 * with RECONNECTING on each retry would clear the host's
                 * re-login prompt. */
                if (ml->state != ML_STATE_RECONNECTING &&
                    ml->state != ML_STATE_AUTH_FAILED &&
                    ml->state != ML_STATE_NEEDS_LOGIN) {
                    ml->state = ML_STATE_RECONNECTING;
                    if (ml->state_cb) {
                        ml->state_cb(ml, ML_STATE_RECONNECTING, ml->state_cb_data);
                    }
                }

                /* Wait on command queue with backoff timeout (interruptible!) */
                ml_coord_cmd_t wake_cmd;
                if (xQueueReceive(ml->coord_cmd_queue, &wake_cmd, pdMS_TO_TICKS(backoff_ms)) == pdTRUE) {
                    if (wake_cmd == ML_CMD_DISCONNECT) {
                        state = COORD_IDLE;
                        ml->state = ML_STATE_IDLE;
                        break;
                    }
                }

                reconnect_attempts++;

                /* Close old connection */
                coord_close_conn(ml);

                /* Reset Noise state for fresh handshake */
                memset(&noise, 0, sizeof(noise));

                state = COORD_STUN_PROBE;
            }
            break;
        }
    }

    /* Cleanup */
    coord_close_conn(ml);
    memset(&noise, 0, sizeof(noise));
    /* Free this instance's long-poll buffers and handshake leftovers, or
     * they stay allocated after stop/destroy. */
    lp_reset(ml);
    free(ml->coord_st.extra_data);
    ml->coord_st.extra_data = NULL;
    ml->coord_st.extra_data_len = 0;

    ESP_LOGI(TAG, "Coord task exiting");
    ml_task_exit(ml, ML_TASK_BIT_COORD);
}
