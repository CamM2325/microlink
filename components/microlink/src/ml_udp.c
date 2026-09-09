/**
 * @file ml_udp.c
 * @brief MicroLink v2 UDP Socket API
 *
 * Provides simple UDP send/receive over the Tailscale VPN tunnel.
 * Uses lwIP UDP PCB bound to the WireGuard netif for encrypted transport.
 *
 * On socket creation, sends CallMeMaybe to all peers to trigger
 * peer-initiated WireGuard handshakes (NAT traversal).
 *
 * Reference: microlink v1 microlink_udp.c
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include <string.h>

static const char *TAG = "ml_udp";

#define UDP_RX_QUEUE_SIZE   4
#define UDP_MAX_PKT_SIZE    1400

/* ============================================================================
 * Internal Types
 * ========================================================================== */

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint8_t data[UDP_MAX_PKT_SIZE];
    size_t len;
    bool valid;
} udp_rx_pkt_t;

struct microlink_udp_socket {
    microlink_t *ml;
    struct udp_pcb *pcb;
    uint16_t local_port;

    /* RX ring buffer */
    udp_rx_pkt_t rx_queue[UDP_RX_QUEUE_SIZE];
    volatile uint8_t rx_head;
    volatile uint8_t rx_tail;

    /* RX notification */
    SemaphoreHandle_t rx_sem;

    /* User callback */
    microlink_udp_rx_cb_t rx_cb;
    void *rx_cb_data;

    /* Dedicated RX task */
    TaskHandle_t rx_task;
    volatile bool rx_running;
};

/* ============================================================================
 * Helpers
 * ========================================================================== */

static void ip_to_lwip(uint32_t ml_ip, ip_addr_t *out) {
    IP4_ADDR(&out->u_addr.ip4,
             (ml_ip >> 24) & 0xFF,
             (ml_ip >> 16) & 0xFF,
             (ml_ip >> 8) & 0xFF,
             ml_ip & 0xFF);
    out->type = IPADDR_TYPE_V4;
}

static uint32_t lwip_to_ip(const ip_addr_t *addr) {
    if (addr->type != IPADDR_TYPE_V4) return 0;
    uint32_t ip = ip4_addr_get_u32(&addr->u_addr.ip4);
    return ((ip & 0xFF) << 24) |
           (((ip >> 8) & 0xFF) << 16) |
           (((ip >> 16) & 0xFF) << 8) |
           ((ip >> 24) & 0xFF);
}

/* ============================================================================
 * lwIP UDP Callback (runs from tcpip thread)
 * ========================================================================== */

static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         const ip_addr_t *addr, u16_t port) {
    microlink_udp_socket_t *sock = (microlink_udp_socket_t *)arg;
    if (!sock || !p) {
        if (p) pbuf_free(p);
        return;
    }

    uint8_t next = (sock->rx_head + 1) % UDP_RX_QUEUE_SIZE;
    if (next == sock->rx_tail) {
        /* Queue full */
        pbuf_free(p);
        return;
    }

    udp_rx_pkt_t *pkt = &sock->rx_queue[sock->rx_head];
    pkt->src_ip = lwip_to_ip(addr);
    pkt->src_port = port;
    pkt->len = (p->tot_len > UDP_MAX_PKT_SIZE) ? UDP_MAX_PKT_SIZE : p->tot_len;
    pbuf_copy_partial(p, pkt->data, pkt->len, 0);
    pkt->valid = true;

    __sync_synchronize();
    sock->rx_head = next;

    if (sock->rx_sem) {
        xSemaphoreGive(sock->rx_sem);
    }

    pbuf_free(p);
}

/* ============================================================================
 * RX Task
 * ========================================================================== */

static void udp_rx_task(void *arg) {
    microlink_udp_socket_t *sock = (microlink_udp_socket_t *)arg;

    while (sock->rx_running) {
        if (xSemaphoreTake(sock->rx_sem, pdMS_TO_TICKS(100)) == pdTRUE) {
            while (sock->rx_tail != sock->rx_head) {
                udp_rx_pkt_t *pkt = &sock->rx_queue[sock->rx_tail];
                if (pkt->valid && sock->rx_cb) {
                    sock->rx_cb(sock, pkt->src_ip, pkt->src_port,
                                pkt->data, pkt->len, sock->rx_cb_data);
                    pkt->valid = false;
                    sock->rx_tail = (sock->rx_tail + 1) % UDP_RX_QUEUE_SIZE;
                } else if (!sock->rx_cb) {
                    break;  /* No callback, leave for polling */
                } else {
                    sock->rx_tail = (sock->rx_tail + 1) % UDP_RX_QUEUE_SIZE;
                }
            }
        }
    }

    vTaskDelete(NULL);
}

/* ============================================================================
 * Public API
 * ========================================================================== */

microlink_udp_socket_t *microlink_udp_create(microlink_t *ml, uint16_t local_port) {
    if (!ml) {
        ESP_LOGE(TAG, "NULL handle");
        return NULL;
    }
    if (ml->state != ML_STATE_CONNECTED) {
        ESP_LOGE(TAG, "Not connected (state=%d)", ml->state);
        return NULL;
    }

    microlink_udp_socket_t *sock = calloc(1, sizeof(microlink_udp_socket_t));
    if (!sock) return NULL;

    sock->ml = ml;
    sock->rx_sem = xSemaphoreCreateCounting(UDP_RX_QUEUE_SIZE, 0);
    if (!sock->rx_sem) {
        free(sock);
        return NULL;
    }

    sock->pcb = udp_new();
    if (!sock->pcb) {
        vSemaphoreDelete(sock->rx_sem);
        free(sock);
        return NULL;
    }

    /* Bind to WG netif */
    if (ml->wg_netif) {
        udp_bind_netif(sock->pcb, (struct netif *)ml->wg_netif);
    }

    /* Bind to VPN IP + port */
    ip_addr_t local_ip;
    ip_to_lwip(ml->vpn_ip, &local_ip);

    err_t err = udp_bind(sock->pcb, &local_ip, local_port);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "udp_bind failed: %d", err);
        udp_remove(sock->pcb);
        vSemaphoreDelete(sock->rx_sem);
        free(sock);
        return NULL;
    }

    sock->local_port = sock->pcb->local_port;
    udp_recv(sock->pcb, udp_recv_cb, sock);

    /* Start RX task on Core 1.
     * Priority was configMAX_PRIORITIES - 2, numerically identical to
     * ESP-IDF's reserved ESP_TASK_BT_CONTROLLER_PRIO tier - see
     * ML_TASK_UDP_RX_PRIO's own comment in microlink_internal.h. */
    sock->rx_running = true;
    if (xTaskCreatePinnedToCore(udp_rx_task, "ml_udp_rx", 4096, sock,
                                 ML_TASK_UDP_RX_PRIO, &sock->rx_task, 1) != pdPASS) {
        sock->rx_running = false;
        sock->rx_task = NULL;
    }

    char ip_buf[16];
    microlink_ip_to_str(ml->vpn_ip, ip_buf);
    ESP_LOGI(TAG, "UDP socket: %s:%u", ip_buf, sock->local_port);

    /* Trigger CallMeMaybe to all peers for WG handshake establishment */
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active) {
            ml_wg_mgr_send_cmm(ml, ml->peers[i].vpn_ip);
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }

    return sock;
}

void microlink_udp_close(microlink_udp_socket_t *sock) {
    if (!sock) return;

    /* Unregister lwIP callback FIRST to prevent use-after-free.
     * The callback runs from tcpip thread and accesses sock->rx_sem,
     * so it must be unregistered before we touch any sock fields. */
    if (sock->pcb) {
        udp_recv(sock->pcb, NULL, NULL);
    }

    if (sock->rx_running) {
        sock->rx_running = false;
        if (sock->rx_sem) xSemaphoreGive(sock->rx_sem);
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    if (sock->pcb) {
        udp_remove(sock->pcb);
    }

    if (sock->rx_sem) vSemaphoreDelete(sock->rx_sem);
    free(sock);
    ESP_LOGI(TAG, "UDP socket closed");
}

esp_err_t microlink_udp_send(microlink_udp_socket_t *sock, uint32_t dest_ip,
                              uint16_t dest_port, const void *data, size_t len) {
    if (!sock || !sock->pcb || !data || len == 0) return ESP_ERR_INVALID_ARG;
    if (len > UDP_MAX_PKT_SIZE) return ESP_ERR_INVALID_SIZE;

    ip_addr_t dest;
    ip_to_lwip(dest_ip, &dest);

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) return ESP_ERR_NO_MEM;

    memcpy(p->payload, data, len);
    err_t err = udp_sendto(sock->pcb, p, &dest, dest_port);
    pbuf_free(p);

    if (err != ERR_OK) {
        if (sock->ml) {
            /* Rate-limit handshake retrigger: max once per 10 seconds per socket.
             * Without this, high-frequency heartbeats each trigger a full WG handshake
             * initiation + CallMeMaybe, flooding the DERP TX queue. */
            static uint64_t last_trigger_ms = 0;
            uint64_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
            if (now_ms - last_trigger_ms > 10000) {
                last_trigger_ms = now_ms;
                ml_wg_mgr_trigger_handshake(sock->ml, dest_ip);
                ml_wg_mgr_send_cmm(sock->ml, dest_ip);
            }
        }
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t microlink_udp_recv(microlink_udp_socket_t *sock, uint32_t *src_ip,
                              uint16_t *src_port, void *buffer, size_t *len,
                              uint32_t timeout_ms) {
    if (!sock || !buffer || !len || *len == 0) return ESP_ERR_INVALID_ARG;

    uint32_t start = xTaskGetTickCount() * portTICK_PERIOD_MS;

    while (1) {
        if (sock->rx_tail != sock->rx_head) {
            udp_rx_pkt_t *pkt = &sock->rx_queue[sock->rx_tail];
            if (pkt->valid) {
                size_t copy = (pkt->len < *len) ? pkt->len : *len;
                memcpy(buffer, pkt->data, copy);
                *len = copy;
                if (src_ip) *src_ip = pkt->src_ip;
                if (src_port) *src_port = pkt->src_port;
                pkt->valid = false;
                sock->rx_tail = (sock->rx_tail + 1) % UDP_RX_QUEUE_SIZE;
                return ESP_OK;
            }
        }

        uint32_t elapsed = (xTaskGetTickCount() * portTICK_PERIOD_MS) - start;
        if (timeout_ms > 0 && elapsed >= timeout_ms) return ESP_ERR_TIMEOUT;
        if (timeout_ms == 0) return ESP_ERR_TIMEOUT;

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

esp_err_t microlink_udp_set_rx_callback(microlink_udp_socket_t *sock,
                                         microlink_udp_rx_cb_t cb, void *user_data) {
    if (!sock) return ESP_ERR_INVALID_ARG;
    sock->rx_cb = cb;
    sock->rx_cb_data = user_data;
    return ESP_OK;
}

uint16_t microlink_udp_get_local_port(const microlink_udp_socket_t *sock) {
    return sock ? sock->local_port : 0;
}
