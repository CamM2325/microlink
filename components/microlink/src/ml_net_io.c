/**
 * @file ml_net_io.c
 * @brief UDP Network I/O Task
 *
 * select() loop for UDP sockets (DISCO, STUN).
 * DERP TLS is handled by the dedicated DERP I/O task (ml_derp.c).
 *
 * Classifies received UDP packets and routes to appropriate queues:
 * - DISCO magic prefix -> disco_rx_queue -> wg_mgr task
 * - STUN response -> stun_rx_queue -> coord task
 * - WireGuard packet -> wg_rx_queue -> wg_mgr task
 *
 * Reference: tailscale/wgengine/magicsock/magicsock.go (receiveIPv4)
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>
#include <errno.h>

static const char *TAG = "ml_net_io";

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

/* Packet classification */
typedef enum {
    PKT_DISCO,
    PKT_STUN,
    PKT_WIREGUARD,
    PKT_UNKNOWN,
} pkt_type_t;

static pkt_type_t classify_packet(const uint8_t *data, size_t len) {
    /* STUN: starts with 0x00 0x01 (binding request) or 0x01 0x01 (binding response) */
    if (len >= 20 && (data[0] == 0x00 || data[0] == 0x01) && data[1] == 0x01) {
        return PKT_STUN;
    }
    /* DISCO: starts with 6-byte magic */
    if (len >= 62 && memcmp(data, DISCO_MAGIC, 6) == 0) {
        return PKT_DISCO;
    }
    /* Everything else is WireGuard */
    if (len >= 4) {
        return PKT_WIREGUARD;
    }
    return PKT_UNKNOWN;
}

static void route_udp_packet(microlink_t *ml, uint8_t *data, size_t len,
                              uint32_t src_ip, uint16_t src_port) {
    pkt_type_t type = classify_packet(data, len);

    /* Was "Log ALL direct UDP packets for debugging" at ESP_LOGI - fires
     * on every single UDP packet received on this socket (DISCO, STUN,
     * and WireGuard alike), the same "every packet at Info" issue as
     * ml_derp.c/ml_wg_mgr.c's own lines. This is the front-door
     * dispatcher for all direct UDP traffic, so it's the highest-volume
     * of the bunch. Moved to Debug. */
    ESP_LOGD(TAG, "UDP RX: %d bytes from %d.%d.%d.%d:%d type=%s hdr=%02x",
             (int)len,
             (int)((src_ip >> 24) & 0xFF), (int)((src_ip >> 16) & 0xFF),
             (int)((src_ip >> 8) & 0xFF), (int)(src_ip & 0xFF),
             (int)src_port,
             type == PKT_DISCO ? "DISCO" : type == PKT_STUN ? "STUN" :
             type == PKT_WIREGUARD ? "WG" : "UNK",
             len > 0 ? data[0] : 0xFF);

    ml_rx_packet_t pkt = {
        .data = data,
        .len = len,
        .src_ip = src_ip,
        .src_port = src_port,
        .via_derp = false,
    };

    switch (type) {
    case PKT_STUN:
        if (xQueueSend(ml->stun_rx_queue, &pkt, 0) != pdTRUE) {
            free(data);  /* Queue full, drop */
        }
        break;
    case PKT_DISCO:
        if (xQueueSend(ml->disco_rx_queue, &pkt, 0) != pdTRUE) {
            free(data);
        }
        break;
    case PKT_WIREGUARD:
        if (xQueueSend(ml->wg_rx_queue, &pkt, 0) != pdTRUE) {
            free(data);
        }
        break;
    default:
        free(data);
        break;
    }
}

void ml_net_io_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "Net I/O task started (Core %d)", xPortGetCoreID());

    uint8_t udp_buf[ML_MAX_PACKET_SIZE + 64];

    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {

        /* ---- UDP sockets via select() ---- */
        fd_set read_fds;
        struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };  /* 50ms select timeout */
        int max_fd = -1;

        FD_ZERO(&read_fds);

        /* Add DISCO UDP socket */
        if (ml->disco_sock4 >= 0) {
            FD_SET(ml->disco_sock4, &read_fds);
            if (ml->disco_sock4 > max_fd) max_fd = ml->disco_sock4;
        }

        /* Add STUN socket (IPv4) */
        if (ml->stun_sock >= 0) {
            FD_SET(ml->stun_sock, &read_fds);
            if (ml->stun_sock > max_fd) max_fd = ml->stun_sock;
        }

        /* Add STUN socket (IPv6) */
        if (ml->stun_sock6 >= 0) {
            FD_SET(ml->stun_sock6, &read_fds);
            if (ml->stun_sock6 > max_fd) max_fd = ml->stun_sock6;
        }

        if (max_fd < 0) {
            /* No UDP sockets yet, just yield */
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        int sel = ml_select_fds(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno != EINTR) {
                ESP_LOGW(TAG, "select error: %d", errno);
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            continue;
        }
        if (sel == 0) continue;  /* Timeout */

        /* Process DISCO UDP socket */
        if (ml->disco_sock4 >= 0 && FD_ISSET(ml->disco_sock4, &read_fds)) {
            struct sockaddr_in src_addr;
            socklen_t addr_len = sizeof(src_addr);
            int n = ml_recvfrom(ml->disco_sock4, udp_buf, sizeof(udp_buf), 0,
                             (struct sockaddr *)&src_addr, &addr_len);
            if (n > 0) {
                uint8_t *pkt_data = malloc(n);
                if (pkt_data) {
                    memcpy(pkt_data, udp_buf, n);
                    uint32_t src_ip = ntohl(src_addr.sin_addr.s_addr);
                    uint16_t src_port = ntohs(src_addr.sin_port);
                    route_udp_packet(ml, pkt_data, n, src_ip, src_port);
                }
            }
        }

        /* Process STUN socket (IPv4) */
        if (ml->stun_sock >= 0 && FD_ISSET(ml->stun_sock, &read_fds)) {
            struct sockaddr_in src_addr;
            socklen_t addr_len = sizeof(src_addr);
            int n = ml_recvfrom(ml->stun_sock, udp_buf, sizeof(udp_buf), 0,
                             (struct sockaddr *)&src_addr, &addr_len);
            if (n > 0) {
                uint8_t *pkt_data = malloc(n);
                if (pkt_data) {
                    memcpy(pkt_data, udp_buf, n);
                    ml_rx_packet_t pkt = {
                        .data = pkt_data,
                        .len = n,
                        .src_ip = ntohl(src_addr.sin_addr.s_addr),
                        .src_port = ntohs(src_addr.sin_port),
                        .via_derp = false,
                    };
                    if (xQueueSend(ml->stun_rx_queue, &pkt, 0) != pdTRUE) {
                        free(pkt_data);
                    }
                }
            }
        }

        /* Process STUN socket (IPv6) */
        if (ml->stun_sock6 >= 0 && FD_ISSET(ml->stun_sock6, &read_fds)) {
            struct sockaddr_in6 src_addr6;
            socklen_t addr_len = sizeof(src_addr6);
            int n = ml_recvfrom(ml->stun_sock6, udp_buf, sizeof(udp_buf), 0,
                             (struct sockaddr *)&src_addr6, &addr_len);
            if (n > 0) {
                uint8_t *pkt_data = malloc(n);
                if (pkt_data) {
                    memcpy(pkt_data, udp_buf, n);
                    ml_rx_packet_t pkt = {
                        .data = pkt_data,
                        .len = n,
                        .src_ip = 0,  /* IPv6 — use parse_response_ipv6 */
                        .src_port = ntohs(src_addr6.sin6_port),
                        .via_derp = false,
                    };
                    if (xQueueSend(ml->stun_rx_queue, &pkt, 0) != pdTRUE) {
                        free(pkt_data);
                    }
                }
            }
        }
    }

    ESP_LOGI(TAG, "Net I/O task exiting");
    vTaskDelete(NULL);
}
