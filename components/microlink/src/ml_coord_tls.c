/**
 * @file ml_coord_tls.c
 * @brief TLS transport for the coordination connection (CONFIG_ML_CTRL_TLS)
 *
 * Wraps the ts2021 Noise handshake in TLS on port 443 for control planes
 * that only expose an HTTPS listener (e.g. Headscale behind a load
 * balancer, such as Lolipop Zero Trust Link). The server certificate is
 * not verified: the control plane is authenticated by the pinned Noise
 * public key, the same trust model as Tailscale's plain port-80 transport
 * (and the same choice ml_derp.c makes for DERP).
 *
 * All functions run on the coord task only — no locking needed.
 */

#include "sdkconfig.h"

#ifdef CONFIG_ML_CTRL_TLS

#include "microlink_internal.h"
#include "esp_log.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include <errno.h>
#include <string.h>

static const char *TAG = "ml_coord_tls";

/* BIO callbacks route through ml_send/ml_recv so the AT-socket backend
 * keeps working. SO_RCVTIMEO/SO_SNDTIMEO on the socket provide timeouts;
 * a timeout surfaces as WANT_READ/WANT_WRITE and propagates out of
 * mbedtls_ssl_read/write, which ml_coord_tls_recv maps back to EAGAIN. */
static int coord_bio_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    int n = ml_send(fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return n;
}

static int coord_bio_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    int n = ml_recv(fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (n == 0) return MBEDTLS_ERR_NET_CONN_RESET;
    return n;
}

int ml_coord_tls_handshake(microlink_t *ml, const char *hostname) {
    ml_coord_tls_t *t = &ml->coord_tls;

    mbedtls_ssl_init(&t->ssl);
    mbedtls_ssl_config_init(&t->ssl_conf);
    mbedtls_entropy_init(&t->entropy);
    mbedtls_ctr_drbg_init(&t->ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&t->ctr_drbg, mbedtls_entropy_func,
                                     &t->entropy, NULL, 0);
    if (ret != 0) goto fail;

    ret = mbedtls_ssl_config_defaults(&t->ssl_conf,
                                       MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) goto fail;

    mbedtls_ssl_conf_authmode(&t->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&t->ssl_conf, mbedtls_ctr_drbg_random, &t->ctr_drbg);

    ret = mbedtls_ssl_setup(&t->ssl, &t->ssl_conf);
    if (ret != 0) goto fail;
    ret = mbedtls_ssl_set_hostname(&t->ssl, hostname);
    if (ret != 0) goto fail;

    t->sockfd = ml->coord_sock;
    mbedtls_ssl_set_bio(&t->ssl, &t->sockfd, coord_bio_send, coord_bio_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&t->ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;  /* Socket timeouts (10s) bound the total wait */
        }
        goto fail;
    }

    t->active = true;
    ESP_LOGI(TAG, "TLS established with %s (suite: %s)",
             hostname, mbedtls_ssl_get_ciphersuite(&t->ssl));
    return 0;

fail:
    {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "TLS handshake with %s failed: -0x%04x (%s)",
                 hostname, (unsigned)-ret, err_buf);
    }
    ml_coord_tls_free(ml);
    return -1;
}

int ml_coord_tls_send(microlink_t *ml, const uint8_t *data, size_t len) {
    ml_coord_tls_t *t = &ml->coord_tls;
    if (!t->active) { errno = ENOTCONN; return -1; }

    size_t sent = 0;
    while (sent < len) {
        int n = mbedtls_ssl_write(&t->ssl, data + sent, len - sent);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            errno = EAGAIN;
            return -1;  /* SNDTIMEO expired mid-write: caller treats as failure */
        }
        if (n <= 0) { errno = EIO; return -1; }
        sent += n;
    }
    return (int)len;
}

/* recv() semantics: >0 bytes read, 0 peer closed, -1 error (EAGAIN on timeout) */
int ml_coord_tls_recv(microlink_t *ml, uint8_t *buf, size_t len) {
    ml_coord_tls_t *t = &ml->coord_tls;
    if (!t->active) { errno = ENOTCONN; return -1; }

    int n = mbedtls_ssl_read(&t->ssl, buf, len);
    if (n > 0) return n;
    if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    errno = EIO;
    return -1;
}

size_t ml_coord_tls_pending(microlink_t *ml) {
    ml_coord_tls_t *t = &ml->coord_tls;
    if (!t->active) return 0;
    return mbedtls_ssl_get_bytes_avail(&t->ssl);
}

void ml_coord_tls_free(microlink_t *ml) {
    ml_coord_tls_t *t = &ml->coord_tls;
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->ssl_conf);
    mbedtls_ctr_drbg_free(&t->ctr_drbg);
    mbedtls_entropy_free(&t->entropy);
    t->sockfd = -1;
    t->active = false;
}

#endif /* CONFIG_ML_CTRL_TLS */
