/**
 * @file ml_udp.c
 * @brief MicroLink v2 UDP Socket API
 *
 * Provides simple UDP send/receive over the Tailscale VPN tunnel.
 * Uses lwIP UDP PCB bound to the WireGuard netif for encrypted transport.
 *
 * On socket creation, asks the wg_mgr task to send CallMeMaybe to all peers
 * to trigger peer-initiated WireGuard handshakes (NAT traversal).
 *
 * Threading model:
 * - The PCB is only touched on tcpip_thread (raw lwIP API is not thread-safe):
 *   create/bind/send/remove go through udp_tcpip_call(), and udp_recv_cb runs
 *   there anyway.
 * - Received packets are handed from tcpip_thread to the consumer through two
 *   FreeRTOS queues of slot pointers (free slots and filled slots), so the
 *   RX task and microlink_udp_recv() callers can consume concurrently.
 * - The per-socket RX task owns the callback invocation. close() removes the
 *   PCB, then joins the RX task; if close() runs on the RX task itself (from
 *   the callback) or the callback outlives the join timeout, the RX task
 *   frees the socket when it exits.
 * - send()/recv()/set_rx_callback() racing close() on another task: each
 *   call holds an in-flight reference (api_refs) and refuses to start once
 *   closing is set. close() waits for the references to drain, waking a
 *   receiver blocked in rx_q with a NULL sentinel, before it removes the PCB
 *   or deletes the queues. If a call is stuck for UDP_CLOSE_JOIN_MS, the
 *   socket is still shut down (PCB removed, no further callbacks) and only
 *   its memory is leaked. set_rx_callback() waiting for cb_lock gives up as
 *   soon as closing is set, so close() from inside the callback can't
 *   deadlock with it. Calls made after close() returned are still invalid
 *   (the handle is freed).
 * - Peer-table work (handshake trigger, CallMeMaybe) is posted to the wg_mgr
 *   task, which owns ml->peers[].
 *
 * Reference: microlink v1 microlink_udp.c
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcpip_priv.h"  /* tcpip_api_call() */
#include "arch/sys_arch.h"         /* sys_thread_tcpip() */
#include <string.h>

static const char *TAG = "ml_udp";

#define UDP_RX_QUEUE_SIZE       4
#define UDP_MAX_PKT_SIZE        1400
#define UDP_RX_TASK_STACK       4096
/* How long close() waits for an in-flight RX callback before handing the
 * final free to the RX task. */
#define UDP_CLOSE_JOIN_MS       5000
/* Handshake retrigger on send failure: at most once per destination per
 * UDP_HS_RETRIGGER_MS, tracking up to UDP_HS_SLOTS destinations per socket. */
#define UDP_HS_RETRIGGER_MS     10000
#define UDP_HS_SLOTS            4

/* ============================================================================
 * Internal Types
 * ========================================================================== */

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t len;
    uint8_t data[UDP_MAX_PKT_SIZE];
} udp_rx_pkt_t;

typedef struct {
    uint32_t ip;
    uint64_t last_ms;       /* 0 = never triggered */
} udp_hs_slot_t;

/* Who frees the socket once the RX task is done with it */
enum {
    UDP_OWNER_SHARED = 0,   /* RX task running, close() not finished */
    UDP_OWNER_CLOSER,       /* RX task exited; close() frees */
    UDP_OWNER_RX_TASK,      /* close() gave up waiting / ran on RX task; RX task frees */
    UDP_OWNER_LEAKED,       /* an API call was stuck in close(): nobody frees */
};

struct microlink_udp_socket {
    microlink_t *ml;
    struct udp_pcb *pcb;            /* tcpip_thread only */
    uint16_t local_port;

    /* RX path: tcpip_thread takes a slot from free_q, fills it and posts it
     * to rx_q; whoever consumes it returns it to free_q. */
    udp_rx_pkt_t rx_slots[UDP_RX_QUEUE_SIZE];
    QueueHandle_t free_q;           /* udp_rx_pkt_t * */
    QueueHandle_t rx_q;             /* udp_rx_pkt_t * */

    /* User callback. cb_lock (recursive) is held while the callback runs, so
     * set_rx_callback() from another task returns only after an in-flight
     * call of the previous callback has finished. */
    SemaphoreHandle_t cb_lock;
    microlink_udp_rx_cb_t rx_cb;
    void *rx_cb_data;

    /* Dedicated RX task and shutdown handshake */
    TaskHandle_t rx_task;
    SemaphoreHandle_t rx_exited;    /* given by RX task on exit when owner == CLOSER */
    volatile bool closing;          /* close() started: API calls are refused */
    volatile bool rx_stop;          /* PCB gone: RX task exits, no more callbacks */
    int owner;                      /* UDP_OWNER_*, accessed atomically */
    int api_refs;                   /* API calls in flight, accessed atomically */

    /* Per-socket, per-destination handshake retrigger limiter */
    portMUX_TYPE hs_mux;
    udp_hs_slot_t hs_slots[UDP_HS_SLOTS];
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

/* Run fn(arg) on tcpip_thread and return its result. tcpip_api_call() takes
 * the core lock when CONFIG_LWIP_TCPIP_CORE_LOCKING is set and otherwise
 * posts to tcpip_thread and waits on the caller's per-thread semaphore. If
 * we already are tcpip_thread (or hold the core lock), call fn directly:
 * waiting on our own mailbox would deadlock. Same detection as
 * wg_udp_sendto_any_ctx() in ml_wg_mgr.c. */
typedef struct {
    struct tcpip_api_call_data call;   /* must be first */
    err_t (*fn)(void *arg);
    void *arg;
} udp_tcpip_call_t;

static err_t udp_tcpip_trampoline(struct tcpip_api_call_data *call) {
    udp_tcpip_call_t *c = (udp_tcpip_call_t *)call;
    return c->fn(c->arg);
}

static err_t udp_tcpip_call(err_t (*fn)(void *arg), void *arg) {
    if (sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
        return fn(arg);
    }
    udp_tcpip_call_t c = { .fn = fn, .arg = arg };
    return tcpip_api_call(udp_tcpip_trampoline, &c.call);
}

/* In-flight reference for an API call. Sequentially consistent with the
 * closing flag in close(): either the call sees closing, or close() sees the
 * reference and waits for it. */
static bool udp_api_enter(microlink_udp_socket_t *sock) {
    __atomic_add_fetch(&sock->api_refs, 1, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&sock->closing, __ATOMIC_SEQ_CST)) {
        __atomic_sub_fetch(&sock->api_refs, 1, __ATOMIC_SEQ_CST);
        return false;
    }
    return true;
}

static void udp_api_leave(microlink_udp_socket_t *sock) {
    __atomic_sub_fetch(&sock->api_refs, 1, __ATOMIC_SEQ_CST);
}

static void udp_sock_free(microlink_udp_socket_t *sock) {
    if (sock->rx_q) vQueueDelete(sock->rx_q);
    if (sock->free_q) vQueueDelete(sock->free_q);
    if (sock->cb_lock) vSemaphoreDelete(sock->cb_lock);
    if (sock->rx_exited) vSemaphoreDelete(sock->rx_exited);
    free(sock);
}

/* ============================================================================
 * lwIP UDP Callback (runs from tcpip thread)
 * ========================================================================== */

static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         const ip_addr_t *addr, u16_t port) {
    (void)pcb;
    microlink_udp_socket_t *sock = (microlink_udp_socket_t *)arg;
    if (!sock || !p) {
        if (p) pbuf_free(p);
        return;
    }

    udp_rx_pkt_t *pkt;
    if (xQueueReceive(sock->free_q, &pkt, 0) != pdTRUE) {
        /* All slots in use: drop */
        pbuf_free(p);
        return;
    }

    pkt->src_ip = lwip_to_ip(addr);
    pkt->src_port = port;
    pkt->len = (p->tot_len > UDP_MAX_PKT_SIZE) ? UDP_MAX_PKT_SIZE : p->tot_len;
    pbuf_copy_partial(p, pkt->data, pkt->len, 0);
    pbuf_free(p);

    /* rx_q and free_q together hold exactly UDP_RX_QUEUE_SIZE slot
     * pointers, so this only fails while close() has a wake-up sentinel
     * queued: give the slot back and drop the packet. */
    if (xQueueSend(sock->rx_q, &pkt, 0) != pdTRUE) {
        xQueueSend(sock->free_q, &pkt, 0);
        return;
    }
    xTaskNotifyGive(sock->rx_task);
}

/* ============================================================================
 * RX Task
 * ========================================================================== */

static void udp_rx_task(void *arg) {
    microlink_udp_socket_t *sock = (microlink_udp_socket_t *)arg;

    while (!sock->rx_stop) {
        /* Woken by udp_recv_cb, set_rx_callback and close */
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        for (;;) {
            xSemaphoreTakeRecursive(sock->cb_lock, portMAX_DELAY);
            if (sock->rx_stop || !sock->rx_cb) {
                /* Stopping, or no callback: leave packets for
                 * microlink_udp_recv() */
                xSemaphoreGiveRecursive(sock->cb_lock);
                break;
            }
            udp_rx_pkt_t *pkt;
            if (xQueueReceive(sock->rx_q, &pkt, 0) != pdTRUE) {
                xSemaphoreGiveRecursive(sock->cb_lock);
                break;
            }
            if (!pkt) {
                /* close()'s wake-up sentinel for blocked receivers */
                xSemaphoreGiveRecursive(sock->cb_lock);
                continue;
            }
            sock->rx_cb(sock, pkt->src_ip, pkt->src_port,
                        pkt->data, pkt->len, sock->rx_cb_data);
            xQueueSend(sock->free_q, &pkt, 0);
            xSemaphoreGiveRecursive(sock->cb_lock);
        }
    }

    /* close() has removed the PCB, so nothing produces any more. Decide who
     * frees the socket: if close() is still waiting, hand it over and signal
     * (that give is our last touch of sock); otherwise close() already left,
     * and the socket is ours. */
    int expected = UDP_OWNER_SHARED;
    if (__atomic_compare_exchange_n(&sock->owner, &expected, UDP_OWNER_CLOSER,
                                    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        xSemaphoreGive(sock->rx_exited);
    } else if (expected == UDP_OWNER_RX_TASK) {
        udp_sock_free(sock);
        ESP_LOGI(TAG, "UDP socket freed by RX task");
    }
    /* UDP_OWNER_LEAKED: a stuck API call may still touch sock; leave it. */
    vTaskDelete(NULL);
}

/* ============================================================================
 * tcpip_thread work
 * ========================================================================== */

typedef struct {
    microlink_udp_socket_t *sock;
    uint16_t local_port;
} udp_open_args_t;

static err_t udp_open_in_tcpip(void *arg) {
    udp_open_args_t *a = (udp_open_args_t *)arg;
    microlink_udp_socket_t *sock = a->sock;
    microlink_t *ml = sock->ml;

    struct udp_pcb *pcb = udp_new();
    if (!pcb) return ERR_MEM;

    /* Bind to WG netif */
    if (ml->wg_netif) {
        udp_bind_netif(pcb, (struct netif *)ml->wg_netif);
    }

    /* Bind to VPN IP + port */
    ip_addr_t local_ip;
    ip_to_lwip(ml->vpn_ip, &local_ip);
    err_t err = udp_bind(pcb, &local_ip, a->local_port);
    if (err != ERR_OK) {
        udp_remove(pcb);
        return err;
    }

    sock->pcb = pcb;
    sock->local_port = pcb->local_port;
    udp_recv(pcb, udp_recv_cb, sock);
    return ERR_OK;
}

static err_t udp_remove_in_tcpip(void *arg) {
    /* Unlinks the PCB from udp_pcbs, so udp_recv_cb can no longer run for it.
     * sock->pcb is cleared here, on tcpip_thread, so a send serialised after
     * this sees NULL instead of a freed PCB. */
    microlink_udp_socket_t *sock = (microlink_udp_socket_t *)arg;
    if (sock->pcb) {
        udp_remove(sock->pcb);
        sock->pcb = NULL;
    }
    return ERR_OK;
}

typedef struct {
    microlink_udp_socket_t *sock;
    ip_addr_t dest;
    uint16_t dest_port;
    const void *data;
    size_t len;
} udp_send_args_t;

static err_t udp_send_in_tcpip(void *arg) {
    udp_send_args_t *a = (udp_send_args_t *)arg;
    /* Read the PCB here, serialised with udp_remove_in_tcpip() */
    struct udp_pcb *pcb = a->sock->pcb;
    if (!pcb) return ERR_CLSD;
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, a->len, PBUF_RAM);
    if (!p) return ERR_MEM;
    memcpy(p->payload, a->data, a->len);
    err_t err = udp_sendto(pcb, p, &a->dest, a->dest_port);
    pbuf_free(p);
    return err;
}

/* True if a handshake retrigger toward dest_ip is due for this socket */
static bool udp_hs_retrigger_due(microlink_udp_socket_t *sock, uint32_t dest_ip) {
    uint64_t now = ml_get_time_ms();
    bool due = false;

    portENTER_CRITICAL(&sock->hs_mux);
    udp_hs_slot_t *slot = NULL;
    udp_hs_slot_t *oldest = &sock->hs_slots[0];
    for (int i = 0; i < UDP_HS_SLOTS; i++) {
        if (sock->hs_slots[i].ip == dest_ip) {
            slot = &sock->hs_slots[i];
            break;
        }
        if (sock->hs_slots[i].last_ms < oldest->last_ms) {
            oldest = &sock->hs_slots[i];
        }
    }
    if (!slot) {
        slot = oldest;
        slot->ip = dest_ip;
        slot->last_ms = 0;
    }
    if (slot->last_ms == 0 || now - slot->last_ms > UDP_HS_RETRIGGER_MS) {
        slot->last_ms = now ? now : 1;
        due = true;
    }
    portEXIT_CRITICAL(&sock->hs_mux);
    return due;
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
    sock->owner = UDP_OWNER_SHARED;
    portMUX_INITIALIZE(&sock->hs_mux);
    sock->free_q = xQueueCreate(UDP_RX_QUEUE_SIZE, sizeof(udp_rx_pkt_t *));
    sock->rx_q = xQueueCreate(UDP_RX_QUEUE_SIZE, sizeof(udp_rx_pkt_t *));
    sock->cb_lock = xSemaphoreCreateRecursiveMutex();
    sock->rx_exited = xSemaphoreCreateBinary();
    if (!sock->free_q || !sock->rx_q || !sock->cb_lock || !sock->rx_exited) {
        udp_sock_free(sock);
        return NULL;
    }
    for (int i = 0; i < UDP_RX_QUEUE_SIZE; i++) {
        udp_rx_pkt_t *slot = &sock->rx_slots[i];
        xQueueSend(sock->free_q, &slot, 0);
    }

    /* Start the RX task before the PCB exists, so udp_recv_cb always has a
     * task to notify. It idles until the first notification.
     * Runs on Core 1 (Core 0 on single-core chips) at ML_TASK_UDP_RX_PRIO
     * (Kconfig ML_UDP_RX_TASK_PRIO) - see microlink_internal.h. */
    if (xTaskCreatePinnedToCore(udp_rx_task, "ml_udp_rx", UDP_RX_TASK_STACK, sock,
                                ML_TASK_UDP_RX_PRIO, &sock->rx_task,
                                ML_TASK_APP_CORE) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create RX task");
        udp_sock_free(sock);
        return NULL;
    }

    /* Create, bind and register the PCB on tcpip_thread */
    udp_open_args_t open_args = { .sock = sock, .local_port = local_port };
    err_t err = udp_tcpip_call(udp_open_in_tcpip, &open_args);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "UDP socket open failed: %d", err);
        /* No PCB, so no producer: stop the RX task through the same
         * handshake close() uses. */
        sock->closing = true;
        sock->rx_stop = true;
        xTaskNotifyGive(sock->rx_task);
        xSemaphoreTake(sock->rx_exited, portMAX_DELAY);
        udp_sock_free(sock);
        return NULL;
    }

    char ip_buf[16];
    microlink_ip_to_str(ml->vpn_ip, ip_buf);
    ESP_LOGI(TAG, "UDP socket: %s:%u", ip_buf, sock->local_port);

    /* Trigger CallMeMaybe to all peers for WG handshake establishment.
     * Runs (paced) on the wg_mgr task, which owns the peer table. */
    if (ml_wg_mgr_post_request(ml, ML_PEER_REQ_CMM_ALL, 0) != ESP_OK) {
        ESP_LOGW(TAG, "Could not queue CallMeMaybe sweep");
    }

    return sock;
}

void microlink_udp_close(microlink_udp_socket_t *sock) {
    if (!sock) return;
    if (__atomic_exchange_n(&sock->closing, true, __ATOMIC_SEQ_CST)) {
        ESP_LOGW(TAG, "UDP socket already closing");
        return;
    }

    /* Let API calls that started before closing was set finish. A receiver
     * blocked on an empty rx_q is woken with a NULL sentinel (re-posted
     * while anyone is still in), so recv() returns instead of waiting on a
     * queue that is about to be deleted. */
    TickType_t drain_start = xTaskGetTickCount();
    while (__atomic_load_n(&sock->api_refs, __ATOMIC_SEQ_CST) > 0) {
        if (uxQueueMessagesWaiting(sock->rx_q) == 0) {
            udp_rx_pkt_t *wake = NULL;
            xQueueSendToFront(sock->rx_q, &wake, 0);
        }
        if (xTaskGetTickCount() - drain_start > pdMS_TO_TICKS(UDP_CLOSE_JOIN_MS)) {
            /* A call is stuck (tcpip_thread not answering?). Freeing now
             * would be a use-after-free for it, so only the memory is
             * leaked: the socket itself is still shut down, so no packet is
             * queued and no callback runs once close() returns. */
            ESP_LOGE(TAG, "UDP close: API call still in flight after %d ms; "
                     "closing the socket but leaking its memory", UDP_CLOSE_JOIN_MS);
            __atomic_store_n(&sock->owner, UDP_OWNER_LEAKED, __ATOMIC_RELEASE);
            /* Don't stop/wake the RX task here: if it exited it could be
             * freed before a later notify. Remove the PCB (no new packets),
             * clear the callback, and leave the RX task parked with the
             * leaked memory. */
            udp_tcpip_call(udp_remove_in_tcpip, sock);
            /* Wait out a callback already running (recursive: fine if we
             * are that callback), then make sure it can't be called again. */
            if (xSemaphoreTakeRecursive(sock->cb_lock, pdMS_TO_TICKS(UDP_CLOSE_JOIN_MS)) == pdTRUE) {
                sock->rx_cb = NULL;
                sock->rx_cb_data = NULL;
                xSemaphoreGiveRecursive(sock->cb_lock);
            } else {
                ESP_LOGE(TAG, "UDP close: RX callback still running after %d ms", UDP_CLOSE_JOIN_MS);
            }
            return;
        }
        vTaskDelay(1);
    }

    /* Remove the PCB: once this returns, udp_recv_cb cannot run for
     * this socket again (it only runs on tcpip_thread, which has now
     * unlinked the PCB). */
    udp_tcpip_call(udp_remove_in_tcpip, sock);
    /* Only now may the RX task exit: udp_recv_cb notifies it by handle. */
    sock->rx_stop = true;

    if (xTaskGetCurrentTaskHandle() == sock->rx_task) {
        /* Called from the RX callback: we are inside udp_rx_task's loop,
         * which still uses sock after the callback returns. Let the task
         * free it on exit. */
        __atomic_store_n(&sock->owner, UDP_OWNER_RX_TASK, __ATOMIC_RELEASE);
        ESP_LOGI(TAG, "UDP socket closed (from RX callback)");
        return;
    }

    /* Wake the RX task and join it */
    xTaskNotifyGive(sock->rx_task);
    if (xSemaphoreTake(sock->rx_exited, pdMS_TO_TICKS(UDP_CLOSE_JOIN_MS)) == pdTRUE) {
        udp_sock_free(sock);
        ESP_LOGI(TAG, "UDP socket closed");
        return;
    }

    int expected = UDP_OWNER_SHARED;
    if (__atomic_compare_exchange_n(&sock->owner, &expected, UDP_OWNER_RX_TASK,
                                    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        /* The callback is still running. It will not be called again; the
         * RX task frees the socket when the callback returns. */
        ESP_LOGW(TAG, "UDP RX callback still running after %d ms; "
                 "socket will be freed when it returns", UDP_CLOSE_JOIN_MS);
        return;
    }

    /* The RX task exited between the timeout and the handover */
    xSemaphoreTake(sock->rx_exited, portMAX_DELAY);
    udp_sock_free(sock);
    ESP_LOGI(TAG, "UDP socket closed");
}

esp_err_t microlink_udp_send(microlink_udp_socket_t *sock, uint32_t dest_ip,
                              uint16_t dest_port, const void *data, size_t len) {
    if (!sock || !data || len == 0) return ESP_ERR_INVALID_ARG;
    if (len > UDP_MAX_PKT_SIZE) return ESP_ERR_INVALID_SIZE;
    if (!udp_api_enter(sock)) return ESP_ERR_INVALID_STATE;

    udp_send_args_t send_args = {
        .sock = sock, .dest_port = dest_port, .data = data, .len = len,
    };
    ip_to_lwip(dest_ip, &send_args.dest);

    esp_err_t ret = ESP_OK;
    err_t err = udp_tcpip_call(udp_send_in_tcpip, &send_args);
    if (err == ERR_MEM) {
        ret = ESP_ERR_NO_MEM;
    } else if (err == ERR_CLSD) {
        ret = ESP_ERR_INVALID_STATE;
    } else if (err != ERR_OK) {
        /* Typically no WG session to this peer yet. Rate-limited per socket
         * and destination: without this, high-frequency heartbeats each
         * trigger a full WG handshake initiation + CallMeMaybe, flooding the
         * DERP TX queue. The work runs on the wg_mgr task. */
        if (sock->ml && udp_hs_retrigger_due(sock, dest_ip)) {
            ml_wg_mgr_post_request(sock->ml, ML_PEER_REQ_HANDSHAKE, dest_ip);
        }
        ret = ESP_FAIL;
    }

    udp_api_leave(sock);
    return ret;
}

esp_err_t microlink_udp_recv(microlink_udp_socket_t *sock, uint32_t *src_ip,
                              uint16_t *src_port, void *buffer, size_t *len,
                              uint32_t timeout_ms) {
    if (!sock || !buffer || !len || *len == 0) return ESP_ERR_INVALID_ARG;
    if (!udp_api_enter(sock)) return ESP_ERR_INVALID_STATE;

    udp_rx_pkt_t *pkt;
    TickType_t ticks = (timeout_ms == 0) ? 0 : pdMS_TO_TICKS(timeout_ms);
    if (timeout_ms > 0 && ticks == 0) ticks = 1;
    if (xQueueReceive(sock->rx_q, &pkt, ticks) != pdTRUE) {
        udp_api_leave(sock);
        return ESP_ERR_TIMEOUT;
    }
    if (!pkt) {
        /* close() woke us: the socket is going away */
        udp_api_leave(sock);
        return ESP_ERR_INVALID_STATE;
    }

    size_t copy = (pkt->len < *len) ? pkt->len : *len;
    memcpy(buffer, pkt->data, copy);
    *len = copy;
    if (src_ip) *src_ip = pkt->src_ip;
    if (src_port) *src_port = pkt->src_port;
    xQueueSend(sock->free_q, &pkt, 0);
    udp_api_leave(sock);
    return ESP_OK;
}

esp_err_t microlink_udp_set_rx_callback(microlink_udp_socket_t *sock,
                                         microlink_udp_rx_cb_t cb, void *user_data) {
    if (!sock) return ESP_ERR_INVALID_ARG;
    if (!udp_api_enter(sock)) return ESP_ERR_INVALID_STATE;

    /* Blocks while the previous callback is running (unless called from
     * it). That callback may itself be in close(), waiting for our
     * reference to drain, so don't wait for cb_lock blindly: give up as
     * soon as closing is set. (The reference is taken first so cb_lock
     * can't be deleted under us while we wait for it.) */
    while (xSemaphoreTakeRecursive(sock->cb_lock, pdMS_TO_TICKS(10)) != pdTRUE) {
        if (__atomic_load_n(&sock->closing, __ATOMIC_SEQ_CST)) {
            udp_api_leave(sock);
            return ESP_ERR_INVALID_STATE;
        }
    }
    if (__atomic_load_n(&sock->closing, __ATOMIC_SEQ_CST)) {
        xSemaphoreGiveRecursive(sock->cb_lock);
        udp_api_leave(sock);
        return ESP_ERR_INVALID_STATE;
    }
    sock->rx_cb = cb;
    sock->rx_cb_data = user_data;
    xSemaphoreGiveRecursive(sock->cb_lock);

    /* Deliver anything that queued up while there was no callback */
    if (cb) xTaskNotifyGive(sock->rx_task);
    udp_api_leave(sock);
    return ESP_OK;
}

uint16_t microlink_udp_get_local_port(const microlink_udp_socket_t *sock) {
    return sock ? sock->local_port : 0;
}
