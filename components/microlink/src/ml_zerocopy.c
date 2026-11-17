/**
 * @file ml_zerocopy.c
 * @brief Zero-copy WireGuard receive path (high-throughput mode)
 *
 * Kconfig: CONFIG_ML_ZERO_COPY_WG
 *
 * Uses a raw lwIP UDP PCB instead of a BSD socket for the DISCO/WG UDP port.
 * The PCB recv callback runs in tcpip_thread and demultiplexes:
 *   - WireGuard packets → wireguardif_network_rx() directly (ZERO COPY)
 *   - DISCO packets → SPSC ring buffer → wg_mgr task
 *   - STUN packets → stun_rx_queue (still uses FreeRTOS queue)
 *
 * The net_io task's select() loop skips disco_sock4 when zero-copy is active.
 * STUN sockets remain BSD-based since STUN is low-frequency.
 *
 * Contributed by dj-oyu (https://github.com/dj-oyu/microlink)
 * Adapted for MicroLink V2 task architecture.
 */

#include "sdkconfig.h"

#ifdef CONFIG_ML_ZERO_COPY_WG

#include "microlink_internal.h"
#include "esp_log.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "wireguardif.h"
#include "wireguard.h"
#include <string.h>

static const char *TAG = "ml_zc";

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

/* STUN magic cookie at bytes 4-7 */
#define STUN_MAGIC_COOKIE 0x2112A442

/* Forward declarations */
extern void wireguardif_network_rx(void *arg, struct udp_pcb *pcb,
                                    struct pbuf *p, const ip_addr_t *addr, u16_t port);
static void zc_send_in_tcpip(void *arg);

/* The instance the receive callback may deliver into. Set on tcpip_thread
 * once the PCB is registered; cleared when it is removed, and by a deinit
 * that could not reach tcpip_thread, so a PCB left registered never touches
 * ml (which the caller may free later) again. */
static microlink_t *s_zc_owner;

/* ============================================================================
 * PCB Receive Callback (runs in tcpip_thread — FAST PATH)
 *
 * Packet classification order matters for performance:
 * 1. WireGuard (most frequent in streaming) → zero-copy inject
 * 2. DISCO (rare control packets) → ring buffer
 * 3. STUN (very rare) → queue
 * ========================================================================== */

static void zc_pcb_recv_cb(void *arg, struct udp_pcb *pcb,
                            struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    microlink_t *ml = __atomic_load_n(&s_zc_owner, __ATOMIC_ACQUIRE);
    if (!ml || ml != (microlink_t *)arg || !p) {
        if (p) pbuf_free(p);
        return;
    }

    uint8_t *data = (uint8_t *)p->payload;
    size_t len = p->tot_len;

    /* Classify packet */
    bool is_disco = (len >= 62 && memcmp(data, DISCO_MAGIC, 6) == 0);

    bool is_stun = false;
    if (!is_disco && len >= 20) {
        uint32_t cookie = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                          ((uint32_t)data[6] << 8) | (uint32_t)data[7];
        is_stun = (cookie == STUN_MAGIC_COOKIE);
    }

    if (is_disco) {
        /* DISCO → copy to SPSC ring buffer (small, rare packets) */
        uint8_t head = __atomic_load_n(&ml->zc.rx_head, __ATOMIC_RELAXED);
        uint8_t next = (head + 1) % ML_ZC_DISCO_RING_SIZE;
        uint8_t tail = __atomic_load_n(&ml->zc.rx_tail, __ATOMIC_ACQUIRE);

        if (next != tail) {
            ml_zc_disco_entry_t *entry = &ml->zc.rx_ring[head];
            entry->len = (len > ML_ZC_DISCO_MAX_PKT) ? ML_ZC_DISCO_MAX_PKT : len;
            pbuf_copy_partial(p, entry->data, entry->len, 0);
            entry->src_ip_nbo = ip_addr_get_ip4_u32(addr);
            entry->src_port = port;
            __atomic_store_n(&ml->zc.rx_head, next, __ATOMIC_RELEASE);
            ml_wg_mgr_wake(ml);
        }
        /* else: ring full, drop (DISCO is retried by design) */
        pbuf_free(p);

    } else if (is_stun) {
        /* STUN → heap-alloc + queue (low frequency, existing path) */
        uint8_t *pkt_data = malloc(len);
        if (pkt_data) {
            pbuf_copy_partial(p, pkt_data, len, 0);
            ml_rx_packet_t pkt = {
                .data = pkt_data,
                .len = len,
                .src_ip = ntohl(ip_addr_get_ip4_u32(addr)),
                .src_port = port,
                .via_derp = false,
            };
            if (xQueueSend(ml->stun_rx_queue, &pkt, 0) != pdTRUE) {
                free(pkt_data);
            }
        }
        pbuf_free(p);

    } else if (len >= 4 && ml->wg_netif) {
        /* WireGuard → ZERO COPY direct injection */
        struct netif *wg_netif = (struct netif *)ml->wg_netif;
        void *device = wg_netif->state;
        if (device) {
            /* wireguardif_network_rx takes ownership of pbuf */
            wireguardif_network_rx(device, NULL, p, addr, port);
            return;  /* DO NOT free — WG owns the pbuf now */
        }
        pbuf_free(p);

    } else {
        pbuf_free(p);
    }
}

/* ============================================================================
 * PCB Init/Deinit (called via tcpip_callback for thread safety)
 * ========================================================================== */

typedef struct {
    microlink_t *ml;
    err_t result;
    SemaphoreHandle_t done;
} zc_setup_ctx_t;

static void zc_pcb_create_in_tcpip(void *arg) {
    zc_setup_ctx_t *ctx = (zc_setup_ctx_t *)arg;
    microlink_t *ml = ctx->ml;

    ml->zc.pcb = udp_new();
    if (!ml->zc.pcb) {
        ctx->result = ERR_MEM;
        xSemaphoreGive(ctx->done);
        return;
    }

    ctx->result = udp_bind(ml->zc.pcb, IP_ADDR_ANY, 0);
    if (ctx->result != ERR_OK) {
        udp_remove(ml->zc.pcb);
        ml->zc.pcb = NULL;
        xSemaphoreGive(ctx->done);
        return;
    }

    ml->zc.local_port = ml->zc.pcb->local_port;

    /* DSCP 46 (EF) → WMM AC_VO for low-latency WiFi scheduling */
    ml->zc.pcb->tos = 0xB8;

    /* Bind to WiFi netif (skip WG netif) */
    extern struct netif *netif_list;
    for (struct netif *n = netif_list; n != NULL; n = n->next) {
        if (n != (struct netif *)ml->wg_netif) {
            udp_bind_netif(ml->zc.pcb, n);
            break;
        }
    }

    /* Register receive callback */
    udp_recv(ml->zc.pcb, zc_pcb_recv_cb, ml);
    __atomic_store_n(&s_zc_owner, ml, __ATOMIC_RELEASE);

    ctx->result = ERR_OK;
    xSemaphoreGive(ctx->done);
}

static void zc_pcb_remove_in_tcpip(void *arg) {
    zc_setup_ctx_t *ctx = (zc_setup_ctx_t *)arg;
    __atomic_store_n(&s_zc_owner, NULL, __ATOMIC_RELEASE);
    if (ctx->ml->zc.pcb) {
        udp_remove(ctx->ml->zc.pcb);
        ctx->ml->zc.pcb = NULL;
    }
    if (ctx->ml->zc.stale_pcb) {
        udp_remove(ctx->ml->zc.stale_pcb);
        ctx->ml->zc.stale_pcb = NULL;
    }
    xSemaphoreGive(ctx->done);
}

/* ============================================================================
 * Public API
 * ========================================================================== */

esp_err_t ml_zerocopy_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing zero-copy WG path");

    if (ml->zc.pcb || ml->zc.stale_pcb) {
        /* A previous deinit could not remove its PCB; clearing ml->zc now
         * would lose it while it is still registered. */
        ESP_LOGE(TAG, "Previous zero-copy PCB still registered, not re-initializing");
        return ESP_ERR_INVALID_STATE;
    }

    /* Clear ring buffer state */
    memset(&ml->zc, 0, sizeof(ml->zc));

    /* Create PCB in tcpip_thread */
    zc_setup_ctx_t ctx = {
        .ml = ml,
        .result = ERR_IF,
        .done = xSemaphoreCreateBinary(),
    };
    if (!ctx.done) return ESP_ERR_NO_MEM;

    err_t err = tcpip_callback(zc_pcb_create_in_tcpip, &ctx);
    if (err != ERR_OK) {
        vSemaphoreDelete(ctx.done);
        return ESP_FAIL;
    }

    xSemaphoreTake(ctx.done, portMAX_DELAY);
    vSemaphoreDelete(ctx.done);

    if (ctx.result != ERR_OK) {
        ESP_LOGE(TAG, "PCB creation failed: %d", ctx.result);
        return ESP_FAIL;
    }

    /* Store the port so coord can advertise it in endpoints */
    ml->disco_local_port = ml->zc.local_port;

    /* Mark disco_sock4 as unused — net_io won't select() on it */
    ml->disco_sock4 = -1;

    ESP_LOGI(TAG, "Zero-copy WG active on port %d", ml->zc.local_port);
    return ESP_OK;
}

esp_err_t ml_zerocopy_deinit(microlink_t *ml) {
    if (!ml->zc.pcb && !ml->zc.stale_pcb) return ESP_OK;

    ESP_LOGI(TAG, "Shutting down zero-copy WG path");

    /* Posted through the tcpip mailbox (not run under the core lock) so any
     * zc_send_in_tcpip() already queued with this PCB runs before it is
     * removed. The semaphore is static, so it cannot fail to allocate (the
     * old code then returned with the PCB still live, its receive callback
     * reading a netif about to be freed), and a failed post is retried
     * rather than waited on forever. Approach from antmanler 446c58f. */
    StaticSemaphore_t done_buf;
    zc_setup_ctx_t ctx = {
        .ml = ml,
        .done = xSemaphoreCreateBinaryStatic(&done_buf),
    };
    err_t err = ERR_MEM;
    for (int i = 0; i < 20; i++) {
        err = tcpip_callback(zc_pcb_remove_in_tcpip, &ctx);
        if (err == ERR_OK) break;
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (err != ERR_OK) {
        /* The PCB stays registered: detach its callback from ml and report
         * it, so the caller doesn't free what the PCB path can still reach.
         * It is parked in stale_pcb: ml->zc.pcb = NULL makes every sender
         * (disco_udp_sendto, ml_zerocopy_send) use the BSD socket instead
         * of a PCB whose replies are now dropped, and the next deinit
         * retries the removal. */
        __atomic_store_n(&s_zc_owner, NULL, __ATOMIC_RELEASE);
        if (ml->zc.pcb) {
            ml->zc.stale_pcb = ml->zc.pcb;
            ml->zc.pcb = NULL;
        }
        ESP_LOGE(TAG, "Could not reach tcpip_thread to remove the zero-copy PCB (%d)", err);
        vSemaphoreDelete(ctx.done);
        return ESP_FAIL;
    }
    xSemaphoreTake(ctx.done, portMAX_DELAY);
    vSemaphoreDelete(ctx.done);
    return ESP_OK;
}

esp_err_t ml_zerocopy_send(microlink_t *ml, const uint8_t *data, size_t len,
                            uint32_t dest_ip, uint16_t dest_port) {
    if (!ml->zc.pcb || len > ML_MAX_PACKET_SIZE) return ESP_ERR_INVALID_ARG;

    /* Acquire TX pool slot (SPSC: wg_mgr writes head, tcpip reads tail) */
    uint8_t head = __atomic_load_n(&ml->zc.tx_head, __ATOMIC_RELAXED);
    uint8_t next = (head + 1) % ML_ZC_TX_POOL_SIZE;
    uint8_t tail = __atomic_load_n(&ml->zc.tx_tail, __ATOMIC_ACQUIRE);

    if (next == tail) {
        return ESP_ERR_NO_MEM;  /* TX pool full */
    }

    ml_zc_tx_ctx_t *ctx = &ml->zc.tx_pool[head];
    ctx->pcb = ml->zc.pcb;
    memcpy(ctx->data, data, len);
    ctx->len = len;
    IP_SET_TYPE_VAL(ctx->dest, IPADDR_TYPE_V4);
    ip4_addr_set_u32(ip_2_ip4(&ctx->dest), htonl(dest_ip));
    ctx->port = dest_port;

    __atomic_store_n(&ml->zc.tx_head, next, __ATOMIC_RELEASE);

    /* Schedule send in tcpip_thread */
    tcpip_callback(zc_send_in_tcpip, ctx);
    return ESP_OK;
}

/* TX callback — runs in tcpip_thread */
static void zc_send_in_tcpip(void *arg) {
    ml_zc_tx_ctx_t *ctx = (ml_zc_tx_ctx_t *)arg;
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, ctx->len, PBUF_RAM);
    if (p) {
        memcpy(p->payload, ctx->data, ctx->len);
        udp_sendto(ctx->pcb, p, &ctx->dest, ctx->port);
        pbuf_free(p);
    }

    /* Find the ml context from the PCB arg to advance tail.
     * We use the parent struct offset trick since ctx is inside ml->zc.tx_pool. */
    microlink_t *ml = (microlink_t *)ctx->pcb->recv_arg;
    if (ml) {
        uint8_t tail = __atomic_load_n(&ml->zc.tx_tail, __ATOMIC_RELAXED);
        __atomic_store_n(&ml->zc.tx_tail,
                         (uint8_t)((tail + 1) % ML_ZC_TX_POOL_SIZE),
                         __ATOMIC_RELEASE);
    }
}

#endif /* CONFIG_ML_ZERO_COPY_WG */
