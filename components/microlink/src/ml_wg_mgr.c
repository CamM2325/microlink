/**
 * @file ml_wg_mgr.c
 * @brief WireGuard Manager Task - Peer Management + DISCO
 *
 * Owns ALL peer state exclusively. Handles:
 * - Peer add/remove/update from coord task (via peer_update_queue)
 * - DISCO ping/pong with rate limiting (matching tailscaled timing)
 * - WireGuard peer provisioning via wireguard-lwip
 * - Direct path discovery and endpoint switching
 *
 * Reference: tailscale/wgengine/magicsock/magicsock.go
 *            tailscale/disco/disco.go
 */

#include "microlink_internal.h"
#include "ml_filter.h"
#include "ml_nat66.h"
#include "ml_config_httpd.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/ip.h"
#include "lwip/tcpip.h"
#include "lwip/mem.h"
#if IP_NAPT
#include "lwip/lwip_napt.h"
#endif
#include "arch/sys_arch.h" /* sys_thread_tcpip() - detects whether we're already on tcpip_thread */
#include "nacl_box.h"
#include "wireguardif.h"
#include "wireguard.h"
#include "wireguard-filter.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#include <errno.h>

/* Forward declaration for zero-copy path */
extern void wireguardif_network_rx(void *arg, struct udp_pcb *pcb,
                                    struct pbuf *p, const ip_addr_t *addr, u16_t port);

static const char *TAG = "ml_wg_mgr";

/* Forward declarations */
static void disco_send_call_me_maybe(microlink_t *ml, int peer_idx);
static void disco_ping_round(microlink_t *ml, int peer_idx, bool force);
static void wg_mgr_send_cmm(microlink_t *ml, uint32_t peer_vpn_ip);
static esp_err_t wg_mgr_trigger_handshake(microlink_t *ml, uint32_t dest_vpn_ip);

/* DISCO message types */
#define DISCO_MSG_PING          0x01
#define DISCO_MSG_PONG          0x02
#define DISCO_MSG_CALL_ME_MAYBE 0x03

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

#define DISCO_TXID_LEN 12
#define DISCO_NONCE_LEN 24

/* Check if an IP (host byte order) is a LAN address */
static inline bool is_lan_ip(uint32_t ip) {
    return ((ip >> 24) == 10) ||                       /* 10.x.x.x */
           ((ip >> 16) == 0xC0A8) ||                   /* 192.168.x.x */
           (((ip >> 16) & 0xFFF0) == 0xAC10);          /* 172.16-31.x.x */
}

/* Longest wg_mgr sleep while idle: bounds the granularity of its periodic
 * work (WG timers every 400 ms, DISCO heartbeats, request pacing). */
#define ML_WG_IDLE_TICK_MS 100

/* Pending DISCO probe tracking */
typedef struct {
    uint8_t txid[DISCO_TXID_LEN];
    uint32_t dest_ip;
    uint16_t dest_port;
    uint64_t sent_ms;
    int peer_index;
    uint32_t round;     /* disco_ping_round() call this probe belongs to */
    bool active;
} disco_probe_t;

/* One probe per destination (see disco_ping_round). Heartbeats on a trusted
 * path use one slot per peer; discovery rounds use one per endpoint plus one
 * via DERP, and an unanswered probe holds its slot for
 * ML_DISCO_PING_TIMEOUT_MS. When the table is full the oldest probe is
 * evicted (see disco_build_ping). */
#define MAX_PENDING_PROBES ((ML_MAX_PEERS * 4) > 64 ? (ML_MAX_PEERS * 4) : 64)
static disco_probe_t pending_probes[MAX_PENDING_PROBES];
static uint32_t s_disco_round;

static uint32_t disco_new_round(void) {
    if (++s_disco_round == 0) s_disco_round = 1;
    return s_disco_round;
}

/* A latency difference below this is noise, not a better path: the RTT
 * measured here includes up to one wg_mgr loop (10 ms) of scheduling delay
 * on each side. */
#define DISCO_RTT_NOISE_MS 10

/* While a direct path is trusted, heartbeats ping only the best path; every
 * endpoint is pinged again at this interval to find a better one (Tailscale:
 * upgradeUDPDirectInterval). */
#define DISCO_FULL_PING_INTERVAL_MS 60000

/* ============================================================================
 * Base64 Key Encoding (wireguard-lwip API requires base64 keys)
 * ========================================================================== */

static void key_to_base64(const uint8_t *key, char *b64, size_t b64_size) {
    size_t olen = 0;
    mbedtls_base64_encode((unsigned char *)b64, b64_size, &olen, key, 32);
    b64[olen] = '\0';
}

/* ============================================================================
 * UDP Send Helper — routes via BSD socket or zero-copy PCB
 *
 * All direct DISCO/WG UDP sends go through this function.
 * dest_ip is HOST byte order, dest_port is HOST byte order.
 * ========================================================================== */

static inline bool disco_has_udp_path(const microlink_t *ml) {
#ifdef CONFIG_ML_ZERO_COPY_WG
    if (ml->zc.pcb) return true;
#endif
    return (ml->disco_sock4 >= 0);
}

static int disco_udp_sendto(microlink_t *ml, const uint8_t *data, size_t len,
                             uint32_t dest_ip_hbo, uint16_t dest_port) {
#ifdef CONFIG_ML_ZERO_COPY_WG
    if (ml->zc.pcb) {
        return (ml_zerocopy_send(ml, data, len, dest_ip_hbo, dest_port) == ESP_OK) ? len : -1;
    }
#endif
    if (ml->disco_sock4 < 0) return -1;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    dest.sin_addr.s_addr = htonl(dest_ip_hbo);

    return ml_sendto(ml->disco_sock4, data, len, MSG_DONTWAIT,
                  (struct sockaddr *)&dest, sizeof(dest));
}

/* ============================================================================
 * WireGuard Output Callbacks (for magicsock mode)
 * ========================================================================== */

/* Called by wireguard-lwip when a peer has no direct endpoint (DERP relay) */
static err_t wg_derp_output_cb(const uint8_t *peer_public_key,
                                const uint8_t *data, size_t len, void *ctx) {
    microlink_t *ml = (microlink_t *)ctx;
    if (!ml || !ml->derp.connected) {
        ESP_LOGW(TAG, "DERP output cb: not connected, dropping %d bytes", (int)len);
        return ERR_CONN;
    }

    /* Log WG handshake initiations with key and one-time hex dump */
    if (len >= 4 && data[0] == 0x01) {
        static int init_dump_count = 0;
        const char *hostname = "?";
        for (int i = 0; i < ml->peer_count; i++) {
            if (memcmp(ml->peers[i].public_key, peer_public_key, 32) == 0) {
                hostname = ml->peers[i].hostname;
                break;
            }
        }
        ESP_LOGD(TAG, "WG INIT -> %s len=%d key=%02x%02x%02x%02x%02x%02x%02x%02x",
                 hostname, (int)len,
                 peer_public_key[0], peer_public_key[1],
                 peer_public_key[2], peer_public_key[3],
                 peer_public_key[4], peer_public_key[5],
                 peer_public_key[6], peer_public_key[7]);

        /* Dump first handshake fully for byte-level verification */
        if (init_dump_count < 1 && len == 148) {
            init_dump_count++;
            /* WG handshake init: type(1) reserved(3) sender(4) ephemeral(32)
             * enc_static(48) enc_timestamp(28) mac1(16) mac2(16) = 148 */
            ESP_LOGD(TAG, "  type=%02x res=%02x%02x%02x sender=%02x%02x%02x%02x",
                     data[0], data[1], data[2], data[3],
                     data[4], data[5], data[6], data[7]);
            ESP_LOGD(TAG, "  ephemeral=%02x%02x%02x%02x...%02x%02x%02x%02x",
                     data[8], data[9], data[10], data[11],
                     data[36], data[37], data[38], data[39]);
            ESP_LOGD(TAG, "  mac1=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     data[116], data[117], data[118], data[119],
                     data[120], data[121], data[122], data[123],
                     data[124], data[125], data[126], data[127],
                     data[128], data[129], data[130], data[131]);
            ESP_LOGD(TAG, "  mac2=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     data[132], data[133], data[134], data[135],
                     data[136], data[137], data[138], data[139],
                     data[140], data[141], data[142], data[143],
                     data[144], data[145], data[146], data[147]);
        }
    }

    esp_err_t err = ml_derp_queue_send(ml, peer_public_key, data, len);
    return (err == ESP_OK) ? ERR_OK : ERR_MEM;
}

/* Called by wireguard-lwip when sending via external UDP socket (magicsock).
 * Uses raw lwIP udp_sendto() instead of BSD sendto() to avoid deadlock
 * when called from the TCPIP thread context (via tcpip_input → ip_input →
 * icmp/tcp reply → wireguardif_output → this callback). BSD sendto() posts
 * a message to the TCPIP thread and waits, which deadlocks if we're already
 * on that thread. */
static struct udp_pcb *s_wg_output_pcb = NULL;

/* Context for dispatching udp_sendto() onto tcpip_thread when wg_udp_output_cb
 * isn't already running there. */
typedef struct {
    struct udp_pcb *pcb;
    struct pbuf *p;
    ip_addr_t dst;
    u16_t port;
    err_t result;
    SemaphoreHandle_t done;
} wg_udp_send_ctx_t;

static void wg_udp_sendto_in_tcpip(void *arg) {
    wg_udp_send_ctx_t *sctx = (wg_udp_send_ctx_t *)arg;
    sctx->result = udp_sendto(sctx->pcb, sctx->p, &sctx->dst, sctx->port);
    xSemaphoreGive(sctx->done);
}

/* Shared by the byte-buffer (#28) and zero-copy pbuf (#33)
 * output callbacks: send directly when already on tcpip_thread, otherwise
 * dispatch and wait. Does not consume p. */
static err_t wg_udp_sendto_any_ctx(struct pbuf *p, const ip_addr_t *dst, u16_t port) {
    if (sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
        return udp_sendto(s_wg_output_pcb, p, dst, port);
    }
    wg_udp_send_ctx_t sctx = {
        .pcb = s_wg_output_pcb, .p = p, .dst = *dst, .port = port,
        .done = xSemaphoreCreateBinary(),
    };
    if (!sctx.done) return ERR_MEM;
    err_t cb_err = tcpip_callback(wg_udp_sendto_in_tcpip, &sctx);
    if (cb_err != ERR_OK) {
        vSemaphoreDelete(sctx.done);
        return cb_err;
    }
    xSemaphoreTake(sctx.done, portMAX_DELAY);
    vSemaphoreDelete(sctx.done);
    return sctx.result;
}

/* Zero-copy WireGuard output. The encrypted pbuf is already PBUF_TRANSPORT
 * with header room, so it goes straight to udp_sendto - no mem_malloc, no
 * linearise, no second pbuf, no second copy. Ownership stays with
 * wireguardif: udp_sendto does not consume q, and this callback is
 * synchronous, so the caller's pbuf_free still applies. */
static err_t wg_udp_output_pbuf_cb(uint32_t dest_ip, uint16_t dest_port,
                                    struct pbuf *q, void *ctx) {
    (void)ctx;
    if (!s_wg_output_pcb) return ERR_CONN;

    ip_addr_t dst;
    IP_SET_TYPE_VAL(dst, IPADDR_TYPE_V4);
    ip4_addr_set_u32(ip_2_ip4(&dst), dest_ip);  /* already network byte order */

    /* #33 called udp_sendto() unconditionally, which bypasses
     * #28's thread-safety dispatch (this callback takes precedence over the
     * byte-buffer one, and also runs on the wg_mgr task for handshakes and
     * keepalives). */
    return wg_udp_sendto_any_ctx(q, &dst, dest_port);
}

static err_t wg_udp_output_cb(uint32_t dest_ip, uint16_t dest_port,
                                const uint8_t *data, size_t len, void *ctx) {
    microlink_t *ml = (microlink_t *)ctx;
    if (!ml) return ERR_CONN;

    /* Log WG packets sent via direct UDP */
    uint32_t ip_host = ntohl(dest_ip);
    ESP_LOGD(TAG, "WG UDP TX: %d bytes -> %d.%d.%d.%d:%d type=%d",
             (int)len,
             (int)((ip_host >> 24) & 0xFF), (int)((ip_host >> 16) & 0xFF),
             (int)((ip_host >> 8) & 0xFF), (int)(ip_host & 0xFF),
             (int)dest_port,
             len >= 1 ? data[0] : -1);

    if (!s_wg_output_pcb) return ERR_CONN;

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) return ERR_MEM;
    memcpy(p->payload, data, len);

    ip_addr_t dst;
    IP_SET_TYPE_VAL(dst, IPADDR_TYPE_V4);
    ip4_addr_set_u32(ip_2_ip4(&dst), dest_ip);  /* already network byte order */

    /* udp_sendto() is raw lwIP core API - not thread-safe unless called from
     * tcpip_thread. This callback runs from two different contexts: from
     * tcpip_thread itself (when an app socket's send routes through the WG
     * netif) and directly from ml_wg_mgr's own task (handshakes, keepalives,
     * periodic housekeeping - confirmed on real hardware via
     * CONFIG_LWIP_CHECK_THREAD_SAFETY, which caught this exact call during a
     * one-shot handshake triggered from process_disco_pong()). Calling
     * tcpip_callback() and blocking for the result when *already* on
     * tcpip_thread would deadlock (tcpip_thread can't service its own queued
     * callback while blocked waiting on it) - hence the explicit check
     * rather than always dispatching. pbuf_alloc()/pbuf_free() aren't core
     * state and don't need this - only the actual PCB send does. */
    err_t err = wg_udp_sendto_any_ctx(p, &dst, dest_port);
    pbuf_free(p);
    return err;
}

/* ============================================================================
 * WireGuard Interface Initialization
 * ========================================================================== */

/* Splices netif into lwIP's global netif_list and brings it up. Like
 * netif_set_up()/netif_set_link_up() themselves, direct netif_list
 * manipulation is core lwIP state and must only happen on tcpip_thread -
 * confirmed on real hardware via CONFIG_LWIP_CHECK_THREAD_SAFETY, which
 * asserts immediately if this runs anywhere else (this used to run inline
 * on ml_wg_mgr's own task). Dispatched via tcpip_callback() + a semaphore,
 * matching the same pattern ml_zerocopy.c already uses for its own PCB
 * setup - this runs once at startup, not per-packet, so the round-trip
 * cost is irrelevant. */
typedef struct {
    struct netif *netif;
    SemaphoreHandle_t done;
    bool napt;          /* subnet router: masquerade forwarded traffic */
    bool napt_failed;
    bool ip6;           /* exit node: tailnet IPv6 address + NAT66 */
    uint8_t ip6addr[16];
} wg_netif_up_ctx_t;

static void wg_netif_bring_up_in_tcpip(void *arg) {
    wg_netif_up_ctx_t *ctx = (wg_netif_up_ctx_t *)arg;
    ctx->netif->next = netif_list;
    netif_list = ctx->netif;
    netif_set_up(ctx->netif);
    netif_set_link_up(ctx->netif);
#if IP_NAPT
    /* lwIP translates forwarded packets whose *input* netif has NAPT on:
     * tailnet traffic for an advertised route leaves the LAN interface
     * with that interface's address as source, and replies arriving there
     * are mapped back and routed into the tunnel. Needs the netif up. */
    if (ctx->napt && !ip_napt_enable_netif(ctx->netif, 1)) ctx->napt_failed = true;
#endif
#ifdef CONFIG_ML_ROUTER_IPV6
    if (ctx->ip6) {
        /* Our tailnet IPv6 address, usable at once (no DAD over a point-to-
         * point tunnel): lwIP then routes the tailnet /64 into the tunnel,
         * and NAT66 maps peers' IPv6 to the LAN address. */
        ip6_addr_t a;
        memset(&a, 0, sizeof(a));
        memcpy(a.addr, ctx->ip6addr, 16);
        s8_t i = -1;
        if (netif_add_ip6_address(ctx->netif, &a, &i) == ERR_OK && i >= 0) {
            /* Set the state directly: netif_ip6_addr_set_state() runs the
             * netif callbacks, and ESP-IDF's (esp_netif_internal_nd6_cb)
             * takes netif->state for an esp_netif_t, which on this netif is
             * the WireGuard device (crash). The address is static (infinite
             * lifetime) and DAD is pointless on the tunnel, so lwIP never
             * changes this state again. */
            ctx->netif->ip6_addr_state[i] = IP6_ADDR_PREFERRED;
            ml_nat66_attach(ctx->netif, ctx->ip6addr);
        }
    }
#endif
    xSemaphoreGive(ctx->done);
}

/* udp_new() (raw lwIP PCB allocation) has the same tcpip_thread-only
 * requirement - confirmed via the same CONFIG_LWIP_CHECK_THREAD_SAFETY
 * assertion once wg_netif_bring_up_in_tcpip() above stopped masking it.
 * Same dispatch pattern; only touches the module-static s_wg_output_pcb,
 * so no per-call context struct needed beyond the semaphore. */
static SemaphoreHandle_t s_wg_output_pcb_done;
static void wg_output_pcb_create_in_tcpip(void *arg) {
    (void)arg;
    s_wg_output_pcb = udp_new();
    if (s_wg_output_pcb) {
        /* Set source port to 51820 (matching DISCO socket) WITHOUT calling
         * udp_bind — avoids registering for input which would steal WG
         * responses from the DISCO BSD socket. udp_sendto uses local_port. */
        s_wg_output_pcb->local_port = 51820;
        /* DSCP 46 (EF) → WMM AC_VO for low-latency WiFi scheduling */
        s_wg_output_pcb->tos = 0xB8;
    }
    xSemaphoreGive(s_wg_output_pcb_done);
}

/* Takes the WG netif out of lwIP and frees its WireGuard device, on
 * tcpip_thread like the bring-up above. Posted through the mailbox (not run
 * under the core lock), so every message queued before it has already run:
 * packet input for the netif (tcpip_inpkt from wireguardif) and loopback
 * polls (netif_poll), which reference the netif and, through replies sent
 * back out of it, the device. Nothing queues new ones afterwards: wg_mgr has
 * stopped and the zero-copy PCB is gone. Approach from antmanler 8de2c80 and
 * ad7cf1c; device free from Csontikka 70cfeba / antmanler 480d905. */
typedef struct {
    struct netif *netif;
    SemaphoreHandle_t done;
} wg_netif_down_ctx_t;

static void wg_netif_remove_in_tcpip(void *arg) {
    wg_netif_down_ctx_t *ctx = (wg_netif_down_ctx_t *)arg;
    struct netif *netif = ctx->netif;
#ifdef CONFIG_ML_ROUTER_IPV6
    ml_nat66_attach(NULL, NULL);
#endif
#if IP_NAPT
    /* Frees the NAPT table if no other netif uses it; needs the netif up */
    if (netif->napt) ip_napt_enable_netif(netif, 0);
#endif
    netif_set_link_down(netif);
    netif_set_down(netif);
    netif_remove(netif);
#if LWIP_NETIF_LOOPBACK
    /* netif_remove leaves looped-back packets queued on the netif. */
    struct pbuf *loop = netif->loop_first;
    netif->loop_first = netif->loop_last = NULL;
    if (loop) pbuf_free(loop);
#endif
    /* Cancels the device timer (sys_untimeout is tcpip_thread-only), then
     * zeroes and frees the ~15 KB device: private key, peers, session keys.
     * It used to be leaked on every stop. */
    wireguardif_free(netif);
    xSemaphoreGive(ctx->done);
}

/* A netif that can't be taken out of lwIP is leaked, but app traffic to
 * 100.64/10 may still route through it on tcpip_thread. Detach the device's
 * output callbacks (their ctx is ml, which microlink_destroy() frees later),
 * so output fails instead of calling back into ml, and try (without
 * blocking) to take the netif down so lwIP stops routing to it. */
static void netif_set_down_in_tcpip(void *arg) {
    netif_set_down((struct netif *)arg);
}

static void wg_abandon_netif(struct netif *netif) {
    wireguardif_detach_outputs(netif);
    if (tcpip_try_callback(netif_set_down_in_tcpip, netif) != ERR_OK) {
        ESP_LOGE(TAG, "Could not post netif_set_down for the leaked WG netif");
    }
}

static void wg_teardown_interface(microlink_t *ml) {
    struct netif *netif = (struct netif *)ml->wg_netif;
    if (!netif) return;

#ifdef CONFIG_ML_ZERO_COPY_WG
    /* The zero-copy receive callback (tcpip_thread) reads ml->wg_netif and
     * feeds its device; remove the PCB first. wg_mgr is its only sender. */
    if (ml_zerocopy_deinit(ml) != ESP_OK) {
        /* The PCB is still registered and tcpip_thread unreachable: the
         * netif can't be taken out of lwIP either. Unpublish it and leak
         * the netif and device rather than free what lwIP may still use. */
        ml->wg_netif = NULL;
        ESP_LOGE(TAG, "Zero-copy PCB still live; leaking the WG netif and device");
        wg_abandon_netif(netif);
        return;
    }
#endif
    /* Unpublish before teardown, not after the free. */
    ml->wg_netif = NULL;

    ML_HEAP_TRACE("wg_mgr: netif teardown begin");
    StaticSemaphore_t done_buf;
    wg_netif_down_ctx_t ctx = {
        .netif = netif,
        .done = xSemaphoreCreateBinaryStatic(&done_buf),
    };
    err_t err = ERR_MEM;
    for (int i = 0; i < 20; i++) {
        err = tcpip_callback(wg_netif_remove_in_tcpip, &ctx);
        if (err == ERR_OK) break;
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (err != ERR_OK) {
        /* Freeing a netif lwIP may still route through would crash the
         * tcpip_thread; leaking it is the lesser evil. */
        ESP_LOGE(TAG, "Could not reach tcpip_thread to remove the WG netif (%d); leaking it", err);
        vSemaphoreDelete(ctx.done);
        wg_abandon_netif(netif);
        return;
    }
    xSemaphoreTake(ctx.done, portMAX_DELAY);
    vSemaphoreDelete(ctx.done);
    free(netif);
    ESP_LOGI(TAG, "WireGuard interface removed and device freed");
    ML_HEAP_TRACE("wg_mgr: netif + device freed");
}

/* Frees the device of a netif that never reached lwIP (bring-up failed).
 * Magicsock mode never arms the device timer and has no device PCB, so no
 * tcpip_thread work is needed. */
static void wg_free_unlinked_device(struct netif *netif) {
    struct wireguard_device *device = (struct wireguard_device *)netif->state;
    if (!device) return;
    netif->state = NULL;
    mbedtls_platform_zeroize(device, sizeof(*device));
    mem_free(device);
}

#ifdef CONFIG_ML_ROUTER_IPV6
static bool exit_node(const microlink_t *ml) {
    return ml_routes_is_exit_node(ml->routes, ml->route_count);
}
/* Forwarding IPv6: built in, an exit node or IPv6 routes, and the control
 * plane gave us a tailnet IPv6 address. */
static bool v6fwd_active(const microlink_t *ml) {
    return ml->has_vpn_ip6 && (exit_node(ml) || ml->route6_count > 0);
}
#endif

/* Add the peer's tailnet IPv6 /128 to its WireGuard peer (exit node only),
 * so its IPv6 passes the inner-source check and replies find it. */
static void wg_peer_sync_ip6(microlink_t *ml, ml_peer_t *p) {
#ifdef CONFIG_ML_ROUTER_IPV6
    if (!v6fwd_active(ml) || !p->has_ip6 || p->ip6_installed || p->wg_peer_index < 0 || !ml->wg_netif) return;
    ip_addr_t ip, mask;
    memset(&ip, 0, sizeof(ip));
    memset(&mask, 0, sizeof(mask));
    IP_SET_TYPE_VAL(ip, IPADDR_TYPE_V6);
    IP_SET_TYPE_VAL(mask, IPADDR_TYPE_V6);
    memcpy(ip_2_ip6(&ip)->addr, p->vpn_ip6, 16);
    memset(ip_2_ip6(&mask)->addr, 0xFF, 16);
    if (wireguardif_add_allowed_ip((struct netif *)ml->wg_netif, (u8_t)p->wg_peer_index, &ip, &mask) == ERR_OK) {
        p->ip6_installed = true;
    } else {
        ESP_LOGW(TAG, "Could not add the IPv6 address of %s to its WireGuard peer", p->hostname);
    }
#else
    (void)ml; (void)p;
#endif
}

/* Tailnet packet filter hooks (run on the RX task / tcpip_thread). */
static bool wg_filter_rx_cb(void *ctx, const uint8_t *pkt, size_t len) {
    /* Keep the filter's local addresses (tailnet IP + advertised routes)
     * in step with ml->vpn_ip, which the coord task can change at any
     * time. The cache (per context: ml_filter is reset by destroy, so a
     * new instance must push again) only saves taking the filter lock per
     * packet; if two receive paths (wg_mgr, zero-copy on tcpip_thread)
     * race on it, both just push the same values. */
    microlink_t *ml = (microlink_t *)ctx;
    uint32_t self = ml->vpn_ip;
    bool v6 = ml->has_vpn_ip6;
    if (self != ml->filter_local_ip || v6 != ml->filter_local_ip6) {
        ml_filter_set_local(self, ml->routes, ml->route_count);
#ifdef CONFIG_ML_ROUTER_IPV6
        /* IPv6 is only set up on the WG netif when we forward it */
        if (v6fwd_active(ml)) {
            ml_filter_set_local6(ml->vpn_ip6, exit_node(ml), ml->routes6, ml->route6_count);
        } else {
            ml_filter_set_local6(NULL, false, NULL, 0);
        }
#endif
        ml->filter_local_ip = self;
        ml->filter_local_ip6 = v6;
    }
    return ml_filter_check_inbound(pkt, len, (uint32_t)ml_get_time_ms());
}

static void wg_filter_tx_cb(void *ctx, const uint8_t *pkt, size_t len) {
    (void)ctx;
    ml_filter_note_outbound(pkt, len, (uint32_t)ml_get_time_ms());
}

static esp_err_t wg_init_interface(microlink_t *ml) {
    /* Convert our WG private key to base64 */
    char privkey_b64[64];
    key_to_base64(ml->wg_private_key, privkey_b64, sizeof(privkey_b64));

    /* Allocate lwIP netif */
    struct netif *netif = (struct netif *)calloc(1, sizeof(struct netif));
    if (!netif) {
        ESP_LOGE(TAG, "Failed to allocate WG netif");
        return ESP_FAIL;
    }

    /* Prepare init data */
    struct wireguardif_init_data wg_init = {0};
    wg_init.private_key = privkey_b64;
    wg_init.listen_port = 51820;
    wg_init.bind_netif = NULL;

    /* Disable internal socket binding (we use magicsock mode) */
    wireguardif_disable_socket_bind();

    /* Initialize WireGuard netif */
    netif->state = &wg_init;
    err_t err = wireguardif_init(netif);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "wireguardif_init failed: %d", err);
        free(netif);
        return ESP_FAIL;
    }

    /* Set IP addresses: our VPN IP (or temporary until we get one) */
    if (ml->vpn_ip != 0) {
        uint8_t a = (ml->vpn_ip >> 24) & 0xFF;
        uint8_t b = (ml->vpn_ip >> 16) & 0xFF;
        uint8_t c = (ml->vpn_ip >> 8) & 0xFF;
        uint8_t d = ml->vpn_ip & 0xFF;
        IP4_ADDR(&netif->ip_addr.u_addr.ip4, a, b, c, d);
    } else {
        IP4_ADDR(&netif->ip_addr.u_addr.ip4, 100, 64, 0, 1);  /* temp */
    }
    IP4_ADDR(&netif->netmask.u_addr.ip4, 255, 192, 0, 0);     /* /10 */
    IP4_ADDR(&netif->gw.u_addr.ip4, 0, 0, 0, 0);

    /* Use tcpip_input so decrypted packets are posted to the TCPIP thread.
     * Required for TCP (esp_http_server sockets) — ip_input from the wg_mgr
     * thread accesses TCP PCB state without synchronization.  The WG output
     * callback uses raw udp_sendto (not BSD sendto) to avoid deadlock. */
    netif->input = tcpip_input;

    /* Add to lwIP netif list and bring up on tcpip_thread (bypass netif_add
     * which wants init callback) - see wg_netif_bring_up_in_tcpip() above. */
    {
        wg_netif_up_ctx_t ctx = { .netif = netif, .done = xSemaphoreCreateBinary(),
                                  .napt = ml->route_count > 0, .napt_failed = false };
#ifdef CONFIG_ML_ROUTER_IPV6
        if (v6fwd_active(ml)) {
            ctx.ip6 = true;
            memcpy(ctx.ip6addr, ml->vpn_ip6, 16);
            /* NAT66 needs a global address on the LAN side: make sure SLAAC
             * runs there (it needs a link-local address first). */
            static const char *const lan_keys[] = { "WIFI_STA_DEF", "ETH_DEF" };
            for (size_t k = 0; k < sizeof(lan_keys) / sizeof(lan_keys[0]); k++) {
                esp_netif_t *lan = esp_netif_get_handle_from_ifkey(lan_keys[k]);
                esp_ip6_addr_t ll;
                if (lan && esp_netif_get_ip6_linklocal(lan, &ll) != ESP_OK) {
                    esp_netif_create_ip6_linklocal(lan);
                }
            }
            ESP_LOGI(TAG, "Forwarding IPv6 (NAT66)%s", exit_node(ml) ? " as exit node" : "");
        }
#endif
        if (!ctx.done) {
            ESP_LOGE(TAG, "Failed to allocate netif-up semaphore");
            wg_free_unlinked_device(netif);
            free(netif);
            return ESP_FAIL;
        }
        err_t cb_err = tcpip_callback(wg_netif_bring_up_in_tcpip, &ctx);
        if (cb_err != ERR_OK) {
            ESP_LOGE(TAG, "tcpip_callback failed to queue netif bring-up: %d", cb_err);
            vSemaphoreDelete(ctx.done);
            wg_free_unlinked_device(netif);
            free(netif);
            return ESP_FAIL;
        }
        xSemaphoreTake(ctx.done, portMAX_DELAY);
        vSemaphoreDelete(ctx.done);
        if (ctx.napt_failed) {
            /* Forwarding without SNAT would send tailnet source addresses
             * onto the LAN: stop advertising the routes instead, which also
             * makes the packet filter drop traffic for them. */
            ESP_LOGE(TAG, "Could not enable NAPT on the WireGuard netif; "
                          "advertised routes disabled");
            ml->route_count = 0;
        }
    }

    /* Create raw UDP PCB for WG output (avoids BSD sendto deadlock on TCPIP
     * thread).  Bind to port 51820 to match the DISCO socket source port. */
    if (!s_wg_output_pcb) {
        /* netif is already linked into netif_list at this
         * point, so it must not be freed on failure; fall through with
         * s_wg_output_pcb == NULL (output cb returns ERR_CONN, DERP still
         * works) - same degraded behaviour as main when udp_new() failed. */
        s_wg_output_pcb_done = xSemaphoreCreateBinary();
        if (!s_wg_output_pcb_done) {
            ESP_LOGE(TAG, "Failed to allocate WG output PCB semaphore");
        } else if (tcpip_callback(wg_output_pcb_create_in_tcpip, NULL) != ERR_OK) {
            ESP_LOGE(TAG, "tcpip_callback failed to queue WG output PCB creation");
            vSemaphoreDelete(s_wg_output_pcb_done);
            s_wg_output_pcb_done = NULL;
        } else {
            xSemaphoreTake(s_wg_output_pcb_done, portMAX_DELAY);
            vSemaphoreDelete(s_wg_output_pcb_done);
            s_wg_output_pcb_done = NULL;
        }
    }

    /* Register output callbacks for magicsock mode */
    wireguardif_set_derp_output(netif, wg_derp_output_cb, ml);
#if defined(CONFIG_ML_PACKET_FILTER_ENFORCE) || defined(CONFIG_ML_PACKET_FILTER_LOG) || \
    defined(CONFIG_ML_SUBNET_ROUTER)
    /* With forwarding on, the destination check in ml_filter is what stops
     * a peer from reaching addresses outside the advertised routes, so the
     * hook is needed even when ACL enforcement is off. */
    wireguardif_set_ip_filter(netif, wg_filter_rx_cb, wg_filter_tx_cb, ml);
#endif
    wireguardif_set_udp_output(netif, wg_udp_output_cb, ml);
    wireguardif_set_udp_output_pbuf(netif, wg_udp_output_pbuf_cb, ml);

    /* On cellular AT socket bridge, force all WG output through DERP relay.
     * AT sockets are TCP-only, so direct UDP is impossible.
     * PPP mode has real lwIP sockets with UDP, so allow direct connections. */
#if CONFIG_ML_ENABLE_CELLULAR
    {
        bool at_ready = ml_at_socket_is_ready();
        ESP_LOGI(TAG, "Cellular mode: at_socket_ready=%d, force_derp=%d", at_ready, at_ready);
        if (at_ready) {
            wireguardif_force_derp_output(netif, true);
            ESP_LOGI(TAG, "Cellular AT socket: forcing DERP output (direct UDP disabled)");
        } else {
            ESP_LOGI(TAG, "Cellular PPP mode: direct UDP ENABLED");
        }
    }
#endif

    ml->wg_netif = netif;

    /* Verify WG device public key matches our expected key */
    {
        struct wireguard_device *dev = (struct wireguard_device *)netif->state;
        if (dev) {
            bool match = (memcmp(dev->public_key, ml->wg_public_key, 32) == 0);
            ESP_LOGI(TAG, "WG device pubkey: %02x%02x%02x%02x... %s ml->wg_public_key",
                     dev->public_key[0], dev->public_key[1],
                     dev->public_key[2], dev->public_key[3],
                     match ? "MATCHES" : "MISMATCH!");
            if (!match) {
                ESP_LOGE(TAG, "  Expected: %02x%02x%02x%02x...",
                         ml->wg_public_key[0], ml->wg_public_key[1],
                         ml->wg_public_key[2], ml->wg_public_key[3]);
            }
        }
    }

    ESP_LOGI(TAG, "WireGuard interface initialized (magicsock mode)");
    return ESP_OK;
}

/* Known gaps (release audit I1, not fixed here): this writes netif->ip_addr
 * from the wg_mgr task rather than on tcpip_thread (it runs once, before any
 * traffic, so it has not mattered in practice), and it is only called at
 * WG init: a VPN IP change received later on the long-poll is never applied
 * to the WG netif. Fixing it means dispatching netif_set_ipaddr() to
 * tcpip_thread and calling this when coord reports a new address. */
static void wg_update_vpn_ip(microlink_t *ml) {
    if (ml->wg_netif && ml->vpn_ip != 0) {
        struct netif *netif = (struct netif *)ml->wg_netif;
        uint8_t a = (ml->vpn_ip >> 24) & 0xFF;
        uint8_t b = (ml->vpn_ip >> 16) & 0xFF;
        uint8_t c = (ml->vpn_ip >> 8) & 0xFF;
        uint8_t d = ml->vpn_ip & 0xFF;
        IP4_ADDR(&netif->ip_addr.u_addr.ip4, a, b, c, d);
    }
}

/* ============================================================================
 * Peer Management (owned exclusively by this task)
 * ========================================================================== */

static int find_peer_by_key(microlink_t *ml, const uint8_t *pubkey) {
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && memcmp(ml->peers[i].public_key, pubkey, 32) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_peer_by_ip(microlink_t *ml, uint32_t vpn_ip) {
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && ml->peers[i].vpn_ip == vpn_ip) {
            return i;
        }
    }
    return -1;
}

static int find_peer_by_disco_key(microlink_t *ml, const uint8_t *disco_key) {
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && memcmp(ml->peers[i].disco_key, disco_key, 32) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_peer_by_node_id(microlink_t *ml, int64_t node_id) {
    if (node_id == 0) return -1;
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && ml->peers[i].node_id == node_id) {
            return i;
        }
    }
    return -1;
}

/* Merge an endpoint list into a peer, preserving per-endpoint last_ping_ms
 * for addresses that are still present (Tailscale's endpointState map isn't
 * wholesale-replaced on a netmap refresh). Returns true if the set changed. */
static bool merge_endpoints(ml_peer_t *p, const ml_peer_update_t *update) {
    if (update->endpoint_count <= 0) return false;
    bool changed = (p->endpoint_count != update->endpoint_count);
    typeof(p->endpoints) old;
    int old_count = p->endpoint_count;
    memcpy(old, p->endpoints, sizeof(old));
    p->endpoint_count = update->endpoint_count;
    for (int i = 0; i < update->endpoint_count && i < ML_MAX_ENDPOINTS; i++) {
        uint64_t preserved_last_ping = 0;
        bool found = false;
        for (int j = 0; j < old_count && j < ML_MAX_ENDPOINTS; j++) {
            if (old[j].ip == update->endpoints[i].ip && old[j].port == update->endpoints[i].port) {
                preserved_last_ping = old[j].last_ping_ms;
                found = true;
                break;
            }
        }
        if (!found) changed = true;
        p->endpoints[i].ip = update->endpoints[i].ip;
        p->endpoints[i].port = update->endpoints[i].port;
        p->endpoints[i].is_ipv6 = update->endpoints[i].is_ipv6;
        p->endpoints[i].last_ping_ms = preserved_last_ping;
    }
    return changed;
}

static void remove_peer_idx(microlink_t *ml, int idx);

static int add_peer(microlink_t *ml, const ml_peer_update_t *update) {
    /* Peer allowlist filter: don't waste WG slots on non-allowed peers.
     * Still process updates for existing peers (they may become allowed later). */
    if (!ml_config_peer_is_allowed(ml->config_httpd, update->vpn_ip)) {
        return -1;  /* Silently skip — peer not in allowlist */
    }

    /* Check if peer already exists */
    int idx = find_peer_by_key(ml, update->public_key);
    if (idx >= 0) {
        ml_peer_t *e = &ml->peers[idx];
        /* Fast path only for a peer that is already installed in WireGuard.
         * Peers preloaded from the NVS cache at boot have no WG slot yet
         * (the netif didn't exist) and must take the full add below, or
         * every handshake from them fails with "peer not found". */
        bool installed = (e->wg_peer_index >= 0) || (ml->wg_netif == NULL);
        if (installed && (update->vpn_ip == 0 || e->vpn_ip == update->vpn_ip)) {
            /* Metadata refresh of a known peer: keep its WireGuard session,
             * validated direct path and per-endpoint ping history. (Re-adding
             * here used to reset all DISCO state on every PeersChanged.) */
            bool persist = false;
            if (update->node_id) e->node_id = update->node_id;
            if (update->netmap_gen) e->netmap_gen = update->netmap_gen;
            if (update->disco_valid && memcmp(e->disco_key, update->disco_key, 32) != 0) {
                memcpy(e->disco_key, update->disco_key, 32);
                e->has_direct_path = false;     /* new disco key: revalidate path */
                e->trust_until_ms = 0;
                persist = true;
            }
            if (update->hostname[0] && strcmp(e->hostname, update->hostname) != 0) {
                strlcpy(e->hostname, update->hostname, sizeof(e->hostname));
                persist = true;
            }
            if (update->derp_region > 0 && e->derp_region != update->derp_region) {
                e->derp_region = update->derp_region;
                persist = true;
            }
            if (update->online_valid) e->online = update->online;
            if (update->has_ip6 && (!e->has_ip6 || memcmp(e->vpn_ip6, update->vpn_ip6, 16) != 0)) {
                memcpy(e->vpn_ip6, update->vpn_ip6, 16);
                e->has_ip6 = true;
                e->ip6_installed = false;
            }
            wg_peer_sync_ip6(ml, e);
            if (merge_endpoints(e, update)) persist = true;
            if (persist) ml_peer_nvs_save(e);   /* only write flash when something changed */
            ESP_LOGD(TAG, "Refreshed peer %s (idx=%d)", e->hostname, idx);
            return idx;
        }
        /* VPN IP changed: the WireGuard allowed-IP must follow, so drop the
         * WG peer and fall through to a full re-add below. */
        if (installed) {
            ESP_LOGI(TAG, "Peer %s changed VPN IP, re-installing", update->hostname);
        }
        if (e->wg_peer_index >= 0 && ml->wg_netif) {
            wireguardif_remove_peer((struct netif *)ml->wg_netif, (u8_t)e->wg_peer_index);
        }
        e->wg_peer_index = -1;
    } else {
        /* Same NodeID under a different node key: the node re-registered or
         * renewed its key and the control plane sent the full record (Peers
         * or PeersChanged) rather than a PeersChangedPatch. Drop the old
         * key's entry and WireGuard peer first, as patch_peer() does for a
         * patched rotation: otherwise the rotated-out key keeps being
         * accepted, and both WireGuard peers own the same VPN IP. */
        int old_idx = find_peer_by_node_id(ml, update->node_id);
        if (old_idx >= 0) {
            ESP_LOGI(TAG, "Peer %s rotated its node key, re-installing",
                     ml->peers[old_idx].hostname);
            remove_peer_idx(ml, old_idx);
        }

        /* Find free slot */
        idx = -1;
        for (int i = 0; i < ML_MAX_PEERS; i++) {
            if (!ml->peers[i].active) {
                idx = i;
                break;
            }
        }

        /* Peer table full — evict LRU non-priority peer if incoming peer is priority */
        if (idx < 0 && ml->config.priority_peer_ip != 0 &&
            update->vpn_ip == ml->config.priority_peer_ip) {
            uint64_t oldest_ms = UINT64_MAX;
            int evict_idx = -1;
            for (int i = 0; i < ML_MAX_PEERS; i++) {
                if (!ml->peers[i].active) continue;
                if (ml->peers[i].vpn_ip == ml->config.priority_peer_ip) continue;
                uint64_t last_activity = ml->peers[i].last_send_ms;
                if (ml->peers[i].last_pong_recv_ms > last_activity)
                    last_activity = ml->peers[i].last_pong_recv_ms;
                if (last_activity < oldest_ms) {
                    oldest_ms = last_activity;
                    evict_idx = i;
                }
            }
            if (evict_idx >= 0) {
                char evict_ip[16];
                microlink_ip_to_str(ml->peers[evict_idx].vpn_ip, evict_ip);
                ESP_LOGW(TAG, "Evicting LRU peer %s (%s) for priority peer %s",
                         ml->peers[evict_idx].hostname, evict_ip, update->hostname);
                /* Full removal like every other path: WireGuard peer, NVS
                 * entry and pending probes (a late pong must not be matched
                 * against the slot's next owner). */
                remove_peer_idx(ml, evict_idx);
                idx = evict_idx;
            }
        }

        /* Table full: an ONLINE peer may replace an OFFLINE one that has no
         * WireGuard session (e.g. expired or long-gone nodes), so stale
         * entries can't lock out live devices. */
        if (idx < 0 && update->online_valid && update->online) {
            struct wireguard_device *dev = ml->wg_netif ?
                (struct wireguard_device *)((struct netif *)ml->wg_netif)->state : NULL;
            for (int i = 0; i < ML_MAX_PEERS; i++) {
                ml_peer_t *c = &ml->peers[i];
                if (!c->active || c->online) continue;
                if (ml->config.priority_peer_ip != 0 && c->vpn_ip == ml->config.priority_peer_ip) continue;
                bool has_session = dev && c->wg_peer_index >= 0 && c->wg_peer_index < WIREGUARD_MAX_PEERS &&
                                   (dev->peers[c->wg_peer_index].curr_keypair.valid ||
                                    dev->peers[c->wg_peer_index].prev_keypair.valid);
                if (has_session) continue;
                ESP_LOGW(TAG, "Peer table full: replacing offline %s with online %s",
                         c->hostname, update->hostname);
                remove_peer_idx(ml, i);
                idx = i;
                if (idx >= ml->peer_count) ml->peer_count = idx + 1;
                break;
            }
        }

        if (idx < 0) {
            ESP_LOGW(TAG, "Peer table full (%d slots), cannot add %s",
                     ML_MAX_PEERS, update->hostname);
            return -1;
        }
        if (idx >= ml->peer_count) {
            ml->peer_count = idx + 1;
        }
    }

    ml_peer_t *p = &ml->peers[idx];
    p->node_id = update->node_id;
    p->netmap_gen = update->netmap_gen;
    p->vpn_ip = update->vpn_ip;
    p->has_ip6 = update->has_ip6;
    if (update->has_ip6) memcpy(p->vpn_ip6, update->vpn_ip6, 16);
    p->ip6_installed = false;
    memcpy(p->public_key, update->public_key, 32);
    memcpy(p->disco_key, update->disco_key, 32);
    strncpy(p->hostname, update->hostname, sizeof(p->hostname) - 1);
    p->hostname[sizeof(p->hostname) - 1] = '\0';
    p->derp_region = update->derp_region;
    p->active = true;
    p->online = update->online;

    /* Copy endpoints. New peer, so nothing to preserve - every entry starts
     * with last_ping_ms=0 ("never pinged yet"), matching a fresh entry in
     * real Tailscale's endpointState map (a zero time.Time). */
    p->endpoint_count = update->endpoint_count;
    for (int i = 0; i < update->endpoint_count && i < ML_MAX_ENDPOINTS; i++) {
        p->endpoints[i].ip = update->endpoints[i].ip;
        p->endpoints[i].port = update->endpoints[i].port;
        p->endpoints[i].is_ipv6 = update->endpoints[i].is_ipv6;
        p->endpoints[i].last_ping_ms = 0;
    }

    /* Initialize DISCO rate limiting state */
    p->last_ping_sent_ms = 0;
    p->last_pong_recv_ms = 0;
    p->trust_until_ms = 0;
    p->last_send_ms = 0;
    p->last_upgrade_ms = 0;
    p->has_direct_path = false;
    p->best_ip = 0;
    p->best_port = 0;
    p->best_rtt_ms = 0;
    p->best_pong_ms = 0;
    p->last_full_ping_ms = 0;
    p->wg_peer_index = -1;
    p->last_hs_kick_ms = 0;

    char ip_str[16];
    microlink_ip_to_str(update->vpn_ip, ip_str);
    ESP_LOGI(TAG, "Peer added: %s (%s) idx=%d endpoints=%d derp=%d key=%02x%02x%02x%02x%02x%02x%02x%02x",
             p->hostname, ip_str, idx, p->endpoint_count, p->derp_region,
             p->public_key[0], p->public_key[1], p->public_key[2], p->public_key[3],
             p->public_key[4], p->public_key[5], p->public_key[6], p->public_key[7]);

    /* Add to wireguard-lwip */
    if (ml->wg_netif) {
        struct netif *netif = (struct netif *)ml->wg_netif;

        /* Convert peer public key to base64 */
        char peer_b64[64];
        key_to_base64(p->public_key, peer_b64, sizeof(peer_b64));

        struct wireguardif_peer wg_peer;
        wireguardif_peer_init(&wg_peer);

        wg_peer.public_key = peer_b64;
        wg_peer.preshared_key = NULL;

        /* Allowed IP: PEER's VPN IP
         * wireguard-lwip uses allowed_ip for TWO purposes:
         * 1. Outbound routing: peer_lookup_by_allowed_ip() matches DESTINATION
         *    IP to find which peer to route to (wireguardif.c:338)
         * 2. Inbound validation: checks decrypted packet SOURCE IP matches
         *    peer's allowed_source_ips (wireguardif.c:507)
         * Must be set to the PEER's VPN IP for both to work correctly. */
        uint8_t ip_a = (p->vpn_ip >> 24) & 0xFF;
        uint8_t ip_b = (p->vpn_ip >> 16) & 0xFF;
        uint8_t ip_c = (p->vpn_ip >> 8) & 0xFF;
        uint8_t ip_d = p->vpn_ip & 0xFF;
        IP4_ADDR(&wg_peer.allowed_ip.u_addr.ip4, ip_a, ip_b, ip_c, ip_d);
        IP4_ADDR(&wg_peer.allowed_mask.u_addr.ip4, 255, 255, 255, 255);

        /* Leave the endpoint BLANK: data output goes via DERP until DISCO
         * validates a direct path (Tailscale semantics). Pre-installing
         * endpoints[0] from the MapResponse advertisement made wireguardif
         * treat an UNVALIDATED address as a working direct path
         * (wireguardif.c peer_output: any non-zero endpoint => direct UDP),
         * so with a CGNAT peer (e.g. PC on cellular) every data reply was
         * fired at an unreachable advertised endpoint and silently lost,
         * while inbound arrived via DERP — one-way tunnel, ping/TCP dead.
         * The validated path install lives in process_disco_pong (only a
         * DIRECT pong sets best_ip -> wireguardif_update_endpoint), which
         * still upgrades us to direct within seconds when it truly works
         * (proven same-LAN). */
        ip_addr_set_any(false, &wg_peer.endpoint_ip);
        wg_peer.endport_port = 0;

        wg_peer.keep_alive = 25;

        /* greatest_timestamp starts at zero on every (re-)install (VPN IP
         * change, key rotation, eviction, sweep and re-add), so one captured
         * initiation from this peer could be replayed once per re-install to
         * move the endpoint until real traffic or DISCO moves it back
         * (release audit I2). That is inherent to WireGuard (a reboot does
         * the same) and is accepted. */
        u8_t wg_peer_idx = WIREGUARDIF_INVALID_INDEX;
        err_t wg_err = wireguardif_add_peer(netif, &wg_peer, &wg_peer_idx);

        if (wg_err == ERR_OK && wg_peer_idx != WIREGUARDIF_INVALID_INDEX) {
            p->wg_peer_index = wg_peer_idx;
            wg_peer_sync_ip6(ml, p);

            /* Verify the WG internal peer key matches what we passed */
            struct wireguard_device *dev = (struct wireguard_device *)netif->state;
            if (dev && wg_peer_idx < WIREGUARD_MAX_PEERS) {
                struct wireguard_peer *wp = &dev->peers[wg_peer_idx];
                bool key_match = (memcmp(wp->public_key, p->public_key, 32) == 0);
                ESP_LOGI(TAG, "WG peer added: wg_idx=%d internal_key=%02x%02x%02x%02x %s",
                         wg_peer_idx,
                         wp->public_key[0], wp->public_key[1],
                         wp->public_key[2], wp->public_key[3],
                         key_match ? "KEY_OK" : "KEY_MISMATCH!");
            }

            /* DON'T initiate handshakes to all peers on add.
             * Tailscale uses lazy peer config: remote peers only add us to their
             * wireguard-go when they need to send traffic. Our handshake initiations
             * to idle peers get silently dropped (peer has no WG entry for us).
             * Instead, we wait for the peer to initiate when they need to reach us.
             * The WG session is established on-demand, matching Tailscale's model. */
            ESP_LOGI(TAG, "WG peer ready (passive), waiting for peer-initiated handshake");
        } else {
            ESP_LOGW(TAG, "wireguardif_add_peer failed: %d", wg_err);
            p->wg_peer_index = -1;
        }
    }

    /* Persist to NVS for fast boot next time */
    ml_peer_nvs_save(p);

    /* Send CallMeMaybe to trigger peer-initiated handshake (NAT traversal).
     * Skip on cellular: our endpoints are behind carrier-grade NAT and
     * unreachable — all traffic goes through DERP relay. */
    if (!ml_at_socket_is_ready()) {
        disco_send_call_me_maybe(ml, idx);
    }

    /* Immediately probe known endpoints (throttled to avoid flooding with 100s of peers).
     * Only force-ping if fewer than 5 peers added in the last second;
     * the periodic probe (every 15s) will handle the rest.
     * Skip on cellular: direct probes fill DERP TX queue (~0.6s each on AT socket),
     * blocking time-critical WG handshake responses. */
    if (!ml_at_socket_is_ready()) {
        static uint64_t last_burst_ms = 0;
        static int burst_count = 0;
        uint64_t add_now = ml_get_time_ms();
        if (add_now - last_burst_ms > 1000) {
            burst_count = 0;
            last_burst_ms = add_now;
        }
        if (burst_count < 5) {
            disco_ping_round(ml, idx, true);
            burst_count++;
        }
    }

    /* Notify app via callback */
    if (ml->peer_cb) {
        microlink_peer_info_t info = {
            .vpn_ip = p->vpn_ip,
            .online = p->online,
            .direct_path = false,
        };
        strncpy(info.hostname, p->hostname, sizeof(info.hostname) - 1);
        memcpy(info.public_key, p->public_key, 32);
        ml->peer_cb(ml, &info, ml->peer_cb_data);
    }

    return idx;
}

/* Fully forget a peer: WireGuard slot, NVS cache entry, pending probes. */
static void remove_peer_idx(microlink_t *ml, int idx) {
    ml_peer_t *p = &ml->peers[idx];
    if (ml->wg_netif && p->wg_peer_index >= 0) {
        wireguardif_remove_peer((struct netif *)ml->wg_netif, (u8_t)p->wg_peer_index);
    }
    p->wg_peer_index = -1;
    ml_peer_nvs_remove(p->public_key);

    /* Pending probes keep a peer index; don't let a late pong for this peer
     * update whichever peer reuses the slot. */
    for (int i = 0; i < MAX_PENDING_PROBES; i++) {
        if (pending_probes[i].active && pending_probes[i].peer_index == idx) {
            pending_probes[i].active = false;
        }
    }

    char ip_str[16];
    microlink_ip_to_str(p->vpn_ip, ip_str);
    ESP_LOGI(TAG, "Peer removed: %s (%s)", p->hostname, ip_str);

    memset(p, 0, sizeof(*p));
    p->wg_peer_index = -1;

    /* Compact peer_count */
    while (ml->peer_count > 0 && !ml->peers[ml->peer_count - 1].active) {
        ml->peer_count--;
    }
}

static void remove_peer(microlink_t *ml, const ml_peer_update_t *update) {
    int idx = update->node_id ? find_peer_by_node_id(ml, update->node_id) : -1;
    if (idx < 0 && update->key_valid) {
        idx = find_peer_by_key(ml, update->public_key);
    }
    if (idx >= 0) {
        remove_peer_idx(ml, idx);
    }
}

static void patch_peer(microlink_t *ml, const ml_peer_update_t *update) {
    int idx = update->node_id ? find_peer_by_node_id(ml, update->node_id) : -1;
    if (idx < 0 && update->key_valid && update->node_id == 0) {
        idx = find_peer_by_key(ml, update->public_key);
    }
    if (idx < 0) return;
    ml_peer_t *p = &ml->peers[idx];

    if (update->key_valid && memcmp(p->public_key, update->public_key, 32) != 0) {
        /* Node key rotated: the WireGuard peer must be re-created under the
         * new key (the old key must stop being accepted). */
        ml_peer_update_t *re = ml_psram_calloc(1, sizeof(ml_peer_update_t));
        if (!re) return;
        re->action = ML_PEER_ADD;
        re->node_id = p->node_id;
        re->netmap_gen = p->netmap_gen;
        re->vpn_ip = p->vpn_ip;
        memcpy(re->public_key, update->public_key, 32);
        re->key_valid = true;
        memcpy(re->disco_key, update->disco_valid ? update->disco_key : p->disco_key, 32);
        re->disco_valid = true;
        strlcpy(re->hostname, p->hostname, sizeof(re->hostname));
        re->derp_region = update->derp_region > 0 ? update->derp_region : p->derp_region;
        re->online = update->online_valid ? update->online : p->online;
        re->online_valid = true;
        const ml_peer_update_t *src_eps = update->endpoint_count > 0 ? update : NULL;
        re->endpoint_count = src_eps ? src_eps->endpoint_count : p->endpoint_count;
        for (int i = 0; i < re->endpoint_count && i < ML_MAX_ENDPOINTS; i++) {
            re->endpoints[i].ip = src_eps ? src_eps->endpoints[i].ip : p->endpoints[i].ip;
            re->endpoints[i].port = src_eps ? src_eps->endpoints[i].port : p->endpoints[i].port;
            re->endpoints[i].is_ipv6 = src_eps ? src_eps->endpoints[i].is_ipv6 : p->endpoints[i].is_ipv6;
        }
        ESP_LOGI(TAG, "Peer %s rotated its node key, re-installing", p->hostname);
        remove_peer_idx(ml, idx);
        add_peer(ml, re);
        free(re);
        return;
    }

    if (update->disco_valid && memcmp(p->disco_key, update->disco_key, 32) != 0) {
        memcpy(p->disco_key, update->disco_key, 32);
        p->has_direct_path = false;
        p->trust_until_ms = 0;
    }
    merge_endpoints(p, update);
    if (update->derp_region > 0) {
        p->derp_region = update->derp_region;
    }
    if (update->online_valid) {
        p->online = update->online;
    }
    ESP_LOGD(TAG, "Peer patched: %s (eps=%d derp=%d online=%d)",
             p->hostname, p->endpoint_count, p->derp_region, p->online);
}

/* End of a full peer list: anything not listed in this generation was removed
 * or revoked on the control plane (or is a stale NVS-cached peer). */
static void sweep_stale_peers(microlink_t *ml, uint32_t gen) {
    int removed = 0;
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && ml->peers[i].netmap_gen != gen) {
            remove_peer_idx(ml, i);
            removed++;
        }
    }
    if (removed) {
        ESP_LOGI(TAG, "Removed %d peer(s) no longer in the netmap", removed);
    }
}

static void process_peer_updates(microlink_t *ml) {
    ml_peer_update_t *update;
    /* One flash write for everything this drain changes in the peer cache
     * (a full netmap of adds, a stale-peer sweep), not one per peer. */
    ml_peer_nvs_batch_begin();
    while (xQueueReceive(ml->peer_update_queue, &update, 0) == pdTRUE) {
        if (!update) continue;
        switch (update->action) {
        case ML_PEER_ADD:
            add_peer(ml, update);
            break;
        case ML_PEER_REMOVE:
            remove_peer(ml, update);
            break;
        case ML_PEER_UPDATE_ENDPOINT:
            patch_peer(ml, update);
            break;
        case ML_PEER_SYNC_DONE:
            sweep_stale_peers(ml, update->netmap_gen);
            break;
        case ML_PEER_REQ_HANDSHAKE:
            wg_mgr_trigger_handshake(ml, update->vpn_ip);
            wg_mgr_send_cmm(ml, update->vpn_ip);
            break;
        case ML_PEER_REQ_CMM_ALL:
            /* (Re)start from the first slot; cmm_sweep_step() paces it. */
            ml->cmm_sweep_active = true;
            ml->cmm_sweep_next = 0;
            break;
        }
        free(update);
    }
    ml_peer_nvs_batch_end();
}

/* Paced CallMeMaybe sweep for ML_PEER_REQ_CMM_ALL: one peer per 50 ms so a
 * large tailnet does not overflow the 16-deep DERP TX queue (each CMM is a
 * non-blocking enqueue). This used to run inline in microlink_udp_create()
 * on the application task, reading peers[] without owning it and blocking
 * the caller for 50 ms per peer. */
#define ML_CMM_SWEEP_INTERVAL_MS 50

static void cmm_sweep_step(microlink_t *ml) {
    if (!ml->cmm_sweep_active) return;
    if (ml_at_socket_is_ready()) {  /* cellular: CMM useless (see wg_mgr_send_cmm) */
        ml->cmm_sweep_active = false;
        return;
    }
    uint64_t now = ml_get_time_ms();
    if (now - ml->cmm_sweep_last_ms < ML_CMM_SWEEP_INTERVAL_MS) return;

    while (ml->cmm_sweep_next < ml->peer_count &&
           !ml->peers[ml->cmm_sweep_next].active) {
        ml->cmm_sweep_next++;
    }
    if (ml->cmm_sweep_next >= ml->peer_count) {
        ml->cmm_sweep_active = false;
        return;
    }
    disco_send_call_me_maybe(ml, ml->cmm_sweep_next++);
    ml->cmm_sweep_last_ms = now;
}

esp_err_t ml_wg_mgr_post_request(microlink_t *ml, int action, uint32_t vpn_ip) {
    if (!ml || !ml->peer_update_queue) return ESP_ERR_INVALID_STATE;
    if (action != ML_PEER_REQ_HANDSHAKE && action != ML_PEER_REQ_CMM_ALL) {
        return ESP_ERR_INVALID_ARG;
    }
    ml_peer_update_t *req = ml_psram_calloc(1, sizeof(ml_peer_update_t));
    if (!req) return ESP_ERR_NO_MEM;
    req->action = action;
    req->vpn_ip = vpn_ip;
    /* Never block the caller: a full queue means wg_mgr is already busy
     * applying a large MapResponse, and the request is only a nudge. */
    if (xQueueSend(ml->peer_update_queue, &req, 0) != pdTRUE) {
        free(req);
        return ESP_ERR_TIMEOUT;
    }
    ml_wg_mgr_wake(ml);
    return ESP_OK;
}

/* ============================================================================
 * DISCO Protocol
 * ========================================================================== */

/* dest_ip/dest_port: the single address this ping is sent to (host byte
 * order), or 0/0 when sent via DERP. Recorded in the probe so that a PONG only
 * proves a direct path to the exact address we pinged (Tailscale: one txid per
 * endpoint, handlePongConnLocked uses the ping's destination sp.to). */
static void disco_build_ping(microlink_t *ml, int peer_idx, uint32_t round,
                               uint32_t dest_ip, uint16_t dest_port,
                               uint8_t *out, size_t *out_len) {
    ml_peer_t *p = &ml->peers[peer_idx];

    /* Plaintext: [type(1)][version(1)][txid(12)][nodekey(32)] = 46 bytes */
    uint8_t plaintext[46];
    plaintext[0] = DISCO_MSG_PING;
    plaintext[1] = 0;  /* version */

    /* Generate random transaction ID */
    uint8_t txid[DISCO_TXID_LEN];
    esp_fill_random(txid, DISCO_TXID_LEN);
    memcpy(plaintext + 2, txid, DISCO_TXID_LEN);
    memcpy(plaintext + 14, ml->wg_public_key, 32);

    /* Generate random nonce */
    uint8_t nonce[DISCO_NONCE_LEN];
    esp_fill_random(nonce, DISCO_NONCE_LEN);

    /* Encrypt with NaCl box: our disco private key -> peer's disco public key */
    uint8_t ciphertext[46 + NACL_BOX_MACBYTES];
    uint8_t disco_shared[32];
    nacl_box_shared_get(disco_shared, p->disco_key, ml->disco_private_key);
    nacl_box_afternm(ciphertext, plaintext, sizeof(plaintext), nonce,
                     disco_shared);

    /* Build packet: magic(6) + our_disco_pubkey(32) + nonce(24) + ciphertext(62) = 124 bytes */
    size_t pos = 0;
    memcpy(out + pos, DISCO_MAGIC, 6); pos += 6;
    memcpy(out + pos, ml->disco_public_key, 32); pos += 32;
    memcpy(out + pos, nonce, DISCO_NONCE_LEN); pos += DISCO_NONCE_LEN;
    memcpy(out + pos, ciphertext, sizeof(ciphertext)); pos += sizeof(ciphertext);
    *out_len = pos;

    /* Track pending probe. A full table evicts the oldest probe rather than
     * dropping this one: dropping the new probe left a heartbeat pong
     * unmatched, trust expired and the peer flapped to DERP and back, while
     * the oldest probe is the one least likely to still be answered. */
    int slot = -1;
    int oldest = 0;
    for (int i = 0; i < MAX_PENDING_PROBES; i++) {
        if (!pending_probes[i].active) {
            slot = i;
            break;
        }
        if (pending_probes[i].sent_ms < pending_probes[oldest].sent_ms) {
            oldest = i;
        }
    }
    if (slot < 0) {
        slot = oldest;
        ESP_LOGD(TAG, "DISCO probe table full (%d slots), evicting the oldest probe",
                 MAX_PENDING_PROBES);
    }
    memcpy(pending_probes[slot].txid, txid, DISCO_TXID_LEN);
    pending_probes[slot].peer_index = peer_idx;
    pending_probes[slot].dest_ip = dest_ip;
    pending_probes[slot].dest_port = dest_port;
    pending_probes[slot].sent_ms = ml_get_time_ms();
    pending_probes[slot].round = round;
    pending_probes[slot].active = true;
    ESP_LOGD(TAG, "Probe registered slot=%d peer=%s txid=%02x%02x%02x%02x",
             slot, p->hostname, txid[0], txid[1], txid[2], txid[3]);
}

static void disco_build_pong(microlink_t *ml, int peer_idx,
                               const uint8_t *txid,
                               uint32_t src_ip, uint16_t src_port,
                               uint8_t *out, size_t *out_len) {
    ml_peer_t *p = &ml->peers[peer_idx];

    /* Plaintext: [type(1)][version(1)][txid(12)][src_addr(18)] = 32 bytes */
    /* src_addr: IPv6-mapped IPv4 (16 bytes) + port (2 bytes big-endian) */
    uint8_t plaintext[32];
    plaintext[0] = DISCO_MSG_PONG;
    plaintext[1] = 0;
    memcpy(plaintext + 2, txid, DISCO_TXID_LEN);

    /* IPv6-mapped IPv4: ::ffff:A.B.C.D */
    memset(plaintext + 14, 0, 10);
    plaintext[24] = 0xff;
    plaintext[25] = 0xff;
    plaintext[26] = (src_ip >> 24) & 0xFF;
    plaintext[27] = (src_ip >> 16) & 0xFF;
    plaintext[28] = (src_ip >> 8) & 0xFF;
    plaintext[29] = src_ip & 0xFF;
    plaintext[30] = (src_port >> 8) & 0xFF;
    plaintext[31] = src_port & 0xFF;

    /* Generate random nonce */
    uint8_t nonce[DISCO_NONCE_LEN];
    esp_fill_random(nonce, DISCO_NONCE_LEN);

    /* Encrypt */
    uint8_t ciphertext[32 + NACL_BOX_MACBYTES];
    uint8_t disco_shared[32];
    nacl_box_shared_get(disco_shared, p->disco_key, ml->disco_private_key);
    nacl_box_afternm(ciphertext, plaintext, sizeof(plaintext), nonce,
                     disco_shared);

    /* Build packet */
    size_t pos = 0;
    memcpy(out + pos, DISCO_MAGIC, 6); pos += 6;
    memcpy(out + pos, ml->disco_public_key, 32); pos += 32;
    memcpy(out + pos, nonce, DISCO_NONCE_LEN); pos += DISCO_NONCE_LEN;
    memcpy(out + pos, ciphertext, sizeof(ciphertext)); pos += sizeof(ciphertext);
    *out_len = pos;
}

/* Ports real Tailscale's endpoint.go sendDiscoPingsLocked()/handleCallMeMaybe()
 * pattern: ping tracking lives per (peer, known-endpoint) - p->endpoints[i].last_ping_ms,
 * the equivalent of endpointState.lastPing - rather than a single per-peer
 * timestamp gating an unconditional "ping every known address" fan-out.
 * `force` bypasses the per-endpoint gate for every endpoint this round
 * (matching handleCallMeMaybe() explicitly zeroing lastPing before its own
 * sendDiscoPingsLocked() call), so a single round can never send more than
 * one probe to an address that was already pinged within
 * ML_DISCO_PING_INTERVAL_MS, no matter how many times this is called back
 * to back - the actual bug (multiple independent probe-table registrations
 * per address per incoming CallMeMaybe) this replaces.
 *
 * SECURITY: every destination gets its own ping (own txid), like Tailscale.
 * A PONG's outer UDP source is not authenticated, so process_disco_pong()
 * only accepts a direct path if the PONG returns from the exact address that
 * txid was sent to. Sharing one txid across destinations let an on-path
 * attacker re-send a captured PONG from its own address and become the
 * peer's "direct path". */
static void disco_ping_round(microlink_t *ml, int peer_idx, bool force) {
    ml_peer_t *p = &ml->peers[peer_idx];
    uint64_t now = ml_get_time_ms();

    bool eligible[ML_MAX_ENDPOINTS] = {0};
    bool any_eligible = false;
    bool best_is_known_endpoint = false;
    for (int i = 0; i < p->endpoint_count && i < ML_MAX_ENDPOINTS; i++) {
        if (p->endpoints[i].is_ipv6 || p->endpoints[i].ip == 0) continue;
        /* MapResponse and NVS endpoints get the same filter as CallMeMaybe
         * ones: never probe tunnel-internal (100.64/10 would be routed into
         * the WG netif), loopback, link-local, multicast or broadcast
         * addresses. A pong from one would set a direct path that
         * wireguardif refuses to use. */
        if (!wg_endpoint_ip4_is_valid_underlay(p->endpoints[i].ip)) continue;
        if (p->endpoints[i].ip == p->best_ip && p->endpoints[i].port == p->best_port) {
            best_is_known_endpoint = true;
        }
        if (force || p->endpoints[i].last_ping_ms == 0 ||
            now - p->endpoints[i].last_ping_ms >= ML_DISCO_PING_INTERVAL_MS) {
            eligible[i] = true;
            any_eligible = true;
        }
    }

    /* best_ip/port is normally already one of the endpoints above (learned
     * from a successful pong to a known address). If it isn't - e.g. a
     * NAT-mapped port only discovered via the pong itself - gate it off the
     * peer-level last_ping_sent_ms instead, same as this function did before
     * per-endpoint tracking existed. */
    bool best_eligible = false;
    if (!best_is_known_endpoint && p->has_direct_path && p->best_ip != 0 && p->best_port != 0 &&
        wg_endpoint_ip4_is_valid_underlay(p->best_ip)) {
        best_eligible = force || now - p->last_ping_sent_ms >= ML_DISCO_PING_INTERVAL_MS;
        if (best_eligible) any_eligible = true;
    }

    if (!any_eligible) {
        return;  /* Every known destination was pinged too recently this round - nothing to do */
    }

    uint8_t pkt[256];
    size_t pkt_len = 0;
    uint32_t round = disco_new_round();

    bool direct_sent = false;
    bool has_udp = disco_has_udp_path(ml);

    if (has_udp) {
        if (best_eligible) {
            disco_build_ping(ml, peer_idx, round, p->best_ip, p->best_port, pkt, &pkt_len);
            disco_udp_sendto(ml, pkt, pkt_len, p->best_ip, p->best_port);
            direct_sent = true;
        }
        p->last_full_ping_ms = now;
        for (int i = 0; i < p->endpoint_count && i < ML_MAX_ENDPOINTS; i++) {
            if (!eligible[i]) continue;  /* also skips IPv6, 0 and non-underlay */
            disco_build_ping(ml, peer_idx, round, p->endpoints[i].ip, p->endpoints[i].port, pkt, &pkt_len);
            int ret = disco_udp_sendto(ml, pkt, pkt_len, p->endpoints[i].ip, p->endpoints[i].port);
            p->endpoints[i].last_ping_ms = now;
            if (!direct_sent) {  /* Log only first direct send per peer */
                ESP_LOGD(TAG, "  direct probe -> %d.%d.%d.%d:%d (%d eps, ret=%d)",
                         (int)((p->endpoints[i].ip >> 24) & 0xFF),
                         (int)((p->endpoints[i].ip >> 16) & 0xFF),
                         (int)((p->endpoints[i].ip >> 8) & 0xFF),
                         (int)(p->endpoints[i].ip & 0xFF),
                         (int)p->endpoints[i].port,
                         p->endpoint_count, ret);
            }
            direct_sent = true;
        }
    } else if (p->endpoint_count > 0) {
        ESP_LOGW(TAG, "  no UDP path for %s (sock4=%d)", p->hostname, ml->disco_sock4);
    }

    /* Send via DERP as fallback (or always for initial probes).
     * Skip DERP for heartbeat pings when direct path is active to avoid
     * DERP pong stealing the probe match from the direct pong. */
    if (!p->has_direct_path || !direct_sent) {
        disco_build_ping(ml, peer_idx, round, 0, 0, pkt, &pkt_len);
        ml_derp_queue_send(ml, p->public_key, pkt, pkt_len);
        ESP_LOGD(TAG, "DISCO PING -> %s via DERP", p->hostname);
    } else {
        ESP_LOGD(TAG, "DISCO PING -> %s via direct %d.%d.%d.%d:%d",
                 p->hostname,
                 (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
                 (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
                 (int)p->best_port);
    }

    p->last_ping_sent_ms = now;
}

/* Heartbeat on a trusted direct path: ping only the best path, like
 * Tailscale's heartbeat. Fanning out to every endpoint each heartbeat filled
 * the probe table (unreachable endpoints hold a slot for the full timeout). */
static void disco_ping_best(microlink_t *ml, int peer_idx) {
    ml_peer_t *p = &ml->peers[peer_idx];
    if (!disco_has_udp_path(ml) || p->best_ip == 0 || p->best_port == 0) {
        disco_ping_round(ml, peer_idx, true);
        return;
    }
    uint64_t now = ml_get_time_ms();
    uint8_t pkt[256];
    size_t pkt_len = 0;
    disco_build_ping(ml, peer_idx, disco_new_round(), p->best_ip, p->best_port, pkt, &pkt_len);
    disco_udp_sendto(ml, pkt, pkt_len, p->best_ip, p->best_port);
    for (int i = 0; i < p->endpoint_count && i < ML_MAX_ENDPOINTS; i++) {
        if (!p->endpoints[i].is_ipv6 && p->endpoints[i].ip == p->best_ip &&
            p->endpoints[i].port == p->best_port) {
            p->endpoints[i].last_ping_ms = now;
        }
    }
    p->last_ping_sent_ms = now;
    ESP_LOGD(TAG, "DISCO heartbeat -> %s via direct %d.%d.%d.%d:%d",
             p->hostname,
             (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
             (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
             (int)p->best_port);
}

static void process_disco_ping(microlink_t *ml, const ml_rx_packet_t *pkt,
                                 const uint8_t *sender_disco_key,
                                 const uint8_t *decrypted, size_t decrypted_len) {
    if (decrypted_len < 14) return;

    /* Extract txid from decrypted payload */
    const uint8_t *txid = decrypted + 2;

    /* Find peer by disco key */
    int peer_idx = find_peer_by_disco_key(ml, sender_disco_key);
    if (peer_idx < 0) {
        ESP_LOGW(TAG, "DISCO ping from unknown peer");
        return;
    }

    ml_peer_t *p = &ml->peers[peer_idx];

    ESP_LOGD(TAG, "DISCO PING from %s (via %s)",
             p->hostname, pkt->via_derp ? "DERP" : "direct");

    /* Build PONG */
    uint8_t pong[256];
    size_t pong_len = 0;
    disco_build_pong(ml, peer_idx, txid, pkt->src_ip, pkt->src_port,
                     pong, &pong_len);

    if (pong_len == 0) return;

    /* Send PONG via ALL paths for maximum reachability (matching v1 + tailscaled):
     * 1. Direct reply to PING source address (opens NAT hole)
     * 2. All known LAN endpoints (fastest path for same-network)
     * 3. DERP relay (guaranteed delivery) */

    bool direct_sent = false;

    /* 1. Direct reply to PING source (if it was direct UDP). Every direct
     * destination below passes the underlay filter (see disco_ping_round). */
    if (!pkt->via_derp && pkt->src_ip != 0 && pkt->src_port != 0 &&
        wg_endpoint_ip4_is_valid_underlay(pkt->src_ip)) {
        disco_udp_sendto(ml, pong, pong_len, pkt->src_ip, pkt->src_port);
        direct_sent = true;
    }

    /* 2. Send to ALL known LAN endpoints (same-network = fastest path) */
    if (disco_has_udp_path(ml)) {
        for (int i = 0; i < p->endpoint_count; i++) {
            if (p->endpoints[i].is_ipv6 || p->endpoints[i].ip == 0) continue;
            if (!is_lan_ip(p->endpoints[i].ip)) continue;   /* LAN ranges are valid underlay */
            /* Skip if this is the same as the ping source (already sent) */
            if (p->endpoints[i].ip == pkt->src_ip &&
                p->endpoints[i].port == pkt->src_port) continue;

            disco_udp_sendto(ml, pong, pong_len, p->endpoints[i].ip, p->endpoints[i].port);
            direct_sent = true;
        }

        /* 2b. Also try public endpoints if no LAN worked */
        if (!direct_sent) {
            for (int i = 0; i < p->endpoint_count; i++) {
                if (p->endpoints[i].is_ipv6 || p->endpoints[i].ip == 0) continue;
                if (is_lan_ip(p->endpoints[i].ip)) continue;
                if (!wg_endpoint_ip4_is_valid_underlay(p->endpoints[i].ip)) continue;

                disco_udp_sendto(ml, pong, pong_len, p->endpoints[i].ip, p->endpoints[i].port);
                direct_sent = true;
                break;  /* Only try one public endpoint */
            }
        }
    }

    /* 3. ALWAYS send via DERP (guaranteed delivery, even if direct worked) */
    ml_derp_queue_send(ml, p->public_key, pong, pong_len);

    ESP_LOGD(TAG, "PONG sent to %s (direct=%s, DERP=yes)",
             p->hostname, direct_sent ? "yes" : "no");
}

/* Is direct path a (a_ip, a_rtt) better than the current best b? Modelled on
 * Tailscale's betterAddr() (endpoint.go), IPv4 only: a private (LAN) address
 * earns 20 points, and the faster path earns its relative latency gain in
 * percent. Equal scores, gains of a point or less and latency differences
 * within DISCO_RTT_NOISE_MS keep the current path (hysteresis), so two
 * equivalent addresses don't take turns being "best". */
static bool disco_path_better(uint32_t a_ip, uint32_t a_rtt, uint32_t b_ip, uint32_t b_rtt) {
    int a = 0, b = 0;
    if (is_lan_ip(a_ip)) a += 20;
    if (is_lan_ip(b_ip)) b += 20;
    if (a_rtt + DISCO_RTT_NOISE_MS <= b_rtt) {
        a += 100 - (int)(((uint64_t)a_rtt * 100) / b_rtt);
    } else if (b_rtt + DISCO_RTT_NOISE_MS <= a_rtt) {
        b += 100 - (int)(((uint64_t)b_rtt * 100) / a_rtt);
    }
    if (a <= 1 && b == 0) return false;
    return a > b;
}

/* Point the peer's WireGuard endpoint at its (new or re-confirmed) best
 * direct path. With a session up this only roams the endpoint, like
 * magicsock moving its bestAddr (wireguardif_set_endpoint() never starts a
 * handshake): a handshake per path change cost two X25519 per heartbeat on
 * a peer reachable at two addresses. Without a session it kicks a
 * (rate-limited) handshake. */
static void disco_apply_direct_path(microlink_t *ml, ml_peer_t *p, bool switched, uint64_t now) {
    if (!ml->wg_netif || p->wg_peer_index < 0) return;
    struct netif *netif = (struct netif *)ml->wg_netif;
    u8_t wg_idx = (u8_t)p->wg_peer_index;

    ip_addr_t ep_ip;
    IP_SET_TYPE_VAL(ep_ip, IPADDR_TYPE_V4);
    ip4_addr_set_u32(ip_2_ip4(&ep_ip), htonl(p->best_ip));

    ip_addr_t cur_ip = IPADDR4_INIT(0);   /* left untouched if the lookup fails */
    u16_t cur_port = 0;
    bool up = wireguardif_peer_is_up(netif, wg_idx, &cur_ip, &cur_port) == ERR_OK;
    bool on_path = IP_IS_V4(&cur_ip) &&
                   ip4_addr_get_u32(ip_2_ip4(&cur_ip)) == htonl(p->best_ip) &&
                   cur_port == p->best_port;

    err_t err;
    if (up && !on_path) {
        /* Always transmit to the DISCO-verified best path, like magicsock
         * sending to bestAddr whatever address the peer's packets arrive
         * from. update_peer_addr() roams peer->ip to the source of each
         * authenticated packet; if that address dies while the best path
         * keeps answering DISCO, leaving the endpoint there black-holed TX
         * (keepalives and rekeys included) for minutes. set_endpoint() only
         * moves the address, no handshake, so a peer that sends from another
         * address just flips it back here once per heartbeat. */
        err = wireguardif_set_endpoint(netif, wg_idx, &ep_ip, p->best_port);
        if (err == ERR_OK && switched) {
            ESP_LOGI(TAG, "WG endpoint SWITCHED to direct: %d.%d.%d.%d:%d for %s",
                     (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
                     (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
                     (int)p->best_port, p->hostname);
        } else if (err == ERR_OK) {
            ESP_LOGD(TAG, "WG endpoint moved back to best path %d.%d.%d.%d:%d for %s",
                     (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
                     (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
                     (int)p->best_port, p->hostname);
        }
    } else {
        /* Session up on the best path already, or no session: keep
         * connect_ip on the best path. */
        err = wireguardif_update_endpoint(netif, wg_idx, &ep_ip, p->best_port);
    }
    if (err != ERR_OK) {
        /* wireguardif refuses non-underlay addresses: don't keep trusting a
         * path the data plane will never use. */
        ESP_LOGW(TAG, "WG refused endpoint %d.%d.%d.%d:%d for %s (%d), dropping direct path",
                 (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
                 (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
                 (int)p->best_port, p->hostname, err);
        p->has_direct_path = false;
        p->trust_until_ms = 0;
        p->best_ip = 0;
        p->best_port = 0;
        return;
    }
    if (up) return;

    ESP_LOGD(TAG, "WG endpoint stored (no session): %d.%d.%d.%d:%d for %s",
             (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
             (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
             (int)p->best_port, p->hostname);
    /* This used to fire exactly one handshake init via a
     * one-shot wireguardif_connect()-then-immediately-
     * clear-active workaround, specifically to dodge
     * wireguard_lwip retrying every 5s forever if the peer
     * had us trimmed. That workaround had its own bug: if
     * this single handshake-init packet was lost, the peer
     * stayed stranded on DERP forever - the one-shot latch
     * never reset and this branch never ran again for that
     * peer, even on a later PONG re-offering the same
     * direct path. Since wireguard_lwip itself now gives up
     * after MAX_TIMER_HANDSHAKES attempts (~REKEY_ATTEMPT_TIME
     * seconds, see wireguard.h), a plain wireguardif_connect()
     * gets real, bounded retries instead of exactly one
     * unretried shot. */
    /* Without a gate this runs on EVERY direct
     * pong (heartbeat = 3 s) while there is no session, and
     * wireguardif_connect() resets handshake_attempts, so the
     * new MAX_TIMER_HANDSHAKES cap never fires: a peer that
     * answers DISCO but not WG gets an initiation every ~3 s
     * forever. Only kick when wireguard_lwip isn't already
     * retrying, and at most once per REKEY_ATTEMPT_TIME. */
    struct wireguard_device *dev = (struct wireguard_device *)netif->state;
    bool retrying = dev && p->wg_peer_index < WIREGUARD_MAX_PEERS &&
                    dev->peers[p->wg_peer_index].active;
    if (!retrying && (p->last_hs_kick_ms == 0 ||
                      now - p->last_hs_kick_ms >= (uint64_t)REKEY_ATTEMPT_TIME * 1000)) {
        p->last_hs_kick_ms = now;
        wireguardif_connect(netif, wg_idx);
        ESP_LOGI(TAG, "WG handshake initiated to %s (direct path discovered)", p->hostname);
    }
}

/* A direct pong from exactly the address its probe was sent to. Each
 * destination has its own txid (see disco_ping_round), so a peer answering on
 * two addresses produces two matching pongs per round; the old code let the
 * last one win and flipped best_ip (and forced a handshake) every heartbeat.
 * Now the first pong of a round that is accepted wins and retires the rest of
 * that round, and a different address only replaces the current best path if
 * it is clearly better or the current one has stopped answering. */
static void disco_handle_direct_pong(microlink_t *ml, int peer_idx, uint32_t round,
                                     uint32_t ip, uint16_t port, uint32_t rtt_ms,
                                     uint64_t now) {
    ml_peer_t *p = &ml->peers[peer_idx];
    bool is_best = (p->best_ip == ip && p->best_port == port);
    bool switched = false;

    if (!is_best) {
        bool have_best = p->has_direct_path && p->best_ip != 0;
        bool best_stale = now - p->best_pong_ms > 2 * (uint64_t)ml->t_disco_heartbeat_ms;
        if (have_best && !best_stale &&
            !disco_path_better(ip, rtt_ms, p->best_ip, p->best_rtt_ms)) {
            /* Keep the current path. Its own probe from this round (if
             * any) is still pending and refreshes trust when it answers. */
            ESP_LOGD(TAG, "DISCO PONG for %s from %d.%d.%d.%d:%d (%lu ms) not better than best (%lu ms)",
                     p->hostname,
                     (int)((ip >> 24) & 0xFF), (int)((ip >> 16) & 0xFF),
                     (int)((ip >> 8) & 0xFF), (int)(ip & 0xFF), (int)port,
                     (unsigned long)rtt_ms, (unsigned long)p->best_rtt_ms);
            return;
        }
        p->best_ip = ip;
        p->best_port = port;
        switched = true;
    }
    if (!p->has_direct_path) switched = true;
    p->best_rtt_ms = rtt_ms;
    p->best_pong_ms = now;
    p->has_direct_path = true;
    p->trust_until_ms = now + ML_DISCO_TRUST_DURATION_MS;

    /* First accepted pong of the round wins: later replies to the same
     * round are not compared against it. */
    for (int j = 0; j < MAX_PENDING_PROBES; j++) {
        if (pending_probes[j].active && pending_probes[j].peer_index == peer_idx &&
            pending_probes[j].round == round) {
            pending_probes[j].active = false;
        }
    }

    disco_apply_direct_path(ml, p, switched, now);
}

static void process_disco_pong(microlink_t *ml, const ml_rx_packet_t *pkt,
                                 const uint8_t *sender_disco_key,
                                 const uint8_t *decrypted, size_t decrypted_len) {
    if (decrypted_len < 14) return;

    const uint8_t *txid = decrypted + 2;
    uint64_t now = ml_get_time_ms();

    /* Match transaction ID */
    bool matched = false;
    for (int i = 0; i < MAX_PENDING_PROBES; i++) {
        if (!pending_probes[i].active) continue;
        if (memcmp(pending_probes[i].txid, txid, DISCO_TXID_LEN) != 0) continue;

        int peer_idx = pending_probes[i].peer_index;
        if (peer_idx < 0 || peer_idx >= ml->peer_count) {
            pending_probes[i].active = false;
            continue;
        }

        ml_peer_t *p = &ml->peers[peer_idx];
        uint64_t rtt_ms = now - pending_probes[i].sent_ms;

        /* The PONG must be boxed by the disco key of the peer we pinged. */
        if (memcmp(sender_disco_key, p->disco_key, 32) != 0) {
            ESP_LOGW(TAG, "DISCO PONG txid match but wrong disco key for %s, ignoring", p->hostname);
            continue;
        }

        /* The outer UDP source of a PONG is NOT authenticated: only treat it as
         * proof of a direct path if it came back from exactly the address this
         * txid was sent to. */
        bool path_ok = !pkt->via_derp && pending_probes[i].dest_ip != 0 &&
                       pkt->src_ip == pending_probes[i].dest_ip &&
                       pkt->src_port == pending_probes[i].dest_port;
        if (!pkt->via_derp && !path_ok) {
            ESP_LOGW(TAG, "DISCO PONG for %s from an address we did not ping, ignoring", p->hostname);
            continue;
        }

        ESP_LOGD(TAG, "DISCO PONG from %s: RTT=%lu ms (via %s)",
                 p->hostname, (unsigned long)rtt_ms,
                 pkt->via_derp ? "DERP" : "direct");

        p->last_pong_recv_ms = now;
        uint32_t round = pending_probes[i].round;
        pending_probes[i].active = false;
        matched = true;

        /* Direct reply from the pinged address: candidate best path */
        if (path_ok) {
            disco_handle_direct_pong(ml, peer_idx, round, pkt->src_ip, pkt->src_port,
                                     (uint32_t)rtt_ms, now);
        }
        break;
    }

    if (!matched) {
        /* Find peer by disco key for logging */
        int peer_idx = find_peer_by_disco_key(ml, sender_disco_key);
        const char *name = peer_idx >= 0 ? ml->peers[peer_idx].hostname : "?";
        int active_count = 0;
        for (int i = 0; i < MAX_PENDING_PROBES; i++) {
            if (pending_probes[i].active) active_count++;
        }
        ESP_LOGD(TAG, "DISCO PONG unmatched from %s (via %s) txid=%02x%02x%02x%02x, active_probes=%d",
                 name, pkt->via_derp ? "DERP" : "direct",
                 txid[0], txid[1], txid[2], txid[3], active_count);
    }
}

static void process_disco_packet(microlink_t *ml, const ml_rx_packet_t *pkt) {
    if (pkt->len < 62) return;  /* magic(6) + key(32) + nonce(24) = 62 minimum */

    /* Verify DISCO magic */
    if (memcmp(pkt->data, DISCO_MAGIC, 6) != 0) return;

    ESP_LOGD(TAG, "DISCO RX: %d bytes via %s, disco_key=%02x%02x%02x%02x",
             (int)pkt->len, pkt->via_derp ? "DERP" : "direct",
             pkt->data[6], pkt->data[7], pkt->data[8], pkt->data[9]);

    /* Extract sender's disco public key */
    const uint8_t *sender_disco_key = pkt->data + 6;

    /* Extract nonce */
    const uint8_t *nonce = pkt->data + 38;

    /* Decrypt ciphertext */
    const uint8_t *ciphertext = pkt->data + 62;
    size_t ciphertext_len = pkt->len - 62;

    if (ciphertext_len < NACL_BOX_MACBYTES) return;

    /* Drop DISCO from disco keys that aren't in our netmap BEFORE any X25519:
     * otherwise random sender keys force a full scalar multiplication per
     * packet (unauthenticated CPU DoS, reachable via DERP). Tailscale's
     * magicsock likewise ignores disco messages from unknown keys. */
    if (find_peer_by_disco_key(ml, sender_disco_key) < 0) {
        ESP_LOGD(TAG, "DISCO from unknown disco key, ignoring");
        return;
    }

    size_t plaintext_len = ciphertext_len - NACL_BOX_MACBYTES;
    uint8_t *plaintext = malloc(plaintext_len);
    if (!plaintext) return;

    /* Cached shared key: the X25519 inside nacl_box_open() costs ~30 ms and
     * would otherwise run on every DISCO packet received. */
    uint8_t disco_shared[32];
    nacl_box_shared_get(disco_shared, sender_disco_key, ml->disco_private_key);

    if (nacl_box_open_afternm(plaintext, ciphertext, ciphertext_len, nonce,
                              disco_shared) != 0) {
        ESP_LOGW(TAG, "DISCO decrypt failed");
        free(plaintext);
        return;
    }

    if (plaintext_len < 2) {
        free(plaintext);
        return;
    }

    uint8_t msg_type = plaintext[0];
    switch (msg_type) {
    case DISCO_MSG_PING:
        process_disco_ping(ml, pkt, sender_disco_key, plaintext, plaintext_len);
        break;
    case DISCO_MSG_PONG:
        process_disco_pong(ml, pkt, sender_disco_key, plaintext, plaintext_len);
        break;
    case DISCO_MSG_CALL_ME_MAYBE:
        {
            /* CallMeMaybe: after type(1)+version(1), payload is N x 18-byte entries
             * Each entry: 16-byte IP (IPv6 or IPv4-mapped) + 2-byte port (big-endian) */
            int peer_idx = find_peer_by_disco_key(ml, sender_disco_key);
            if (peer_idx < 0) {
                ESP_LOGW(TAG, "CallMeMaybe from unknown peer");
                break;
            }

            const uint8_t *ep_data = plaintext + 2;
            size_t ep_data_len = plaintext_len - 2;
            int ep_count = ep_data_len / 18;

            ESP_LOGD(TAG, "CallMeMaybe from %s: %d endpoints (udp_path=%d, at_sock=%d)",
                     ml->peers[peer_idx].hostname, ep_count,
                     disco_has_udp_path(ml), ml_at_socket_is_ready());

            /* This used to reply with our own CallMeMaybe here ("bidirectional
             * NAT traversal") - disco_send_call_me_maybe() has no rate limit
             * of its own, and this reply is exactly what the *other* side's
             * own identical reply-to-CMM logic reacts to, so two peers that
             * ever exchange one CMM start an unbounded mutual reply loop
             * (confirmed on real hardware: ~150-250ms cadence, sustained for
             * about a minute after a cold-start convergence, only stopping
             * once a direct path won or a packet in the chain happened to
             * drop). Real Tailscale's handleCallMeMaybe() (endpoint.go) never
             * does this - a CallMeMaybe there is only ever sent proactively
             * from the heartbeat path (sendDiscoPingsLocked's own
             * sendCallMeMaybe flag), never as a receive-triggered reply.
             * Removed rather than rate-limited, matching the reference
             * design instead of bolting a throttle onto behavior that
             * shouldn't exist at all. Bidirectional discovery is still
             * covered by this file's own independent, one-directional
             * triggers (the initial add_peer burst, the post-STUN one-shot
             * broadcast, ML_PEER_REQ_HANDSHAKE from microlink_tcp_connect()) -
             * none of them receive-triggered, so none can form this loop. */

            /* Merge each offered endpoint into p->endpoints[] - matching real
             * Tailscale's handleCallMeMaybe(), which updates/inserts into its
             * persistent per-endpoint endpointState map rather than firing an
             * independent, untracked ping per endpoint per CallMeMaybe
             * received. An existing (ip,port) gets its last_ping_ms zeroed to
             * force a fresh probe this round despite ML_DISCO_PING_INTERVAL_MS
             * (matching handleCallMeMaybe() explicitly zeroing lastPing); a
             * genuinely new one is appended if there's room. This is what
             * fixed a real incident found on real hardware: the old
             * per-endpoint disco_build_ping() loop registered one brand-new,
             * untracked probe-table entry per offered endpoint on *every*
             * CallMeMaybe, with nothing recognizing "I already have an
             * outstanding probe to this address" - repeated CMMs during a
             * cold-start convergence filled a 32-slot probe table within
             * about a minute.
             * Skip merging/probing on cellular: direct UDP impossible there. */
            for (int i = 0; !ml_at_socket_is_ready() && i < ep_count && i < ML_MAX_ENDPOINTS; i++) {
                const uint8_t *entry = ep_data + (i * 18);
                uint16_t port = (entry[16] << 8) | entry[17];

                /* Check for IPv4-mapped IPv6: ::ffff:A.B.C.D */
                bool is_v4_mapped = true;
                for (int j = 0; j < 10; j++) {
                    if (entry[j] != 0) { is_v4_mapped = false; break; }
                }
                if (entry[10] != 0xff || entry[11] != 0xff) is_v4_mapped = false;

                ESP_LOGD(TAG, "  CMM ep[%d]: v4mapped=%d port=%d bytes=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                         i, is_v4_mapped, port,
                         entry[0], entry[1], entry[2], entry[3],
                         entry[4], entry[5], entry[6], entry[7],
                         entry[8], entry[9], entry[10], entry[11],
                         entry[12], entry[13], entry[14], entry[15]);

                if (!is_v4_mapped || port == 0) continue;
                {
                    uint32_t cand = ((uint32_t)entry[12] << 24) | ((uint32_t)entry[13] << 16) |
                                    ((uint32_t)entry[14] << 8) | entry[15];
                    /* Never probe/install tunnel-internal, loopback, multicast or
                     * broadcast addresses offered in a CallMeMaybe. */
                    if (!wg_endpoint_ip4_is_valid_underlay(cand)) continue;
                }

                uint32_t ip = ((uint32_t)entry[12] << 24) |
                              ((uint32_t)entry[13] << 16) |
                              ((uint32_t)entry[14] << 8) |
                              (uint32_t)entry[15];

                ml_peer_t *cmm_peer = &ml->peers[peer_idx];
                int match = -1;
                for (int k = 0; k < cmm_peer->endpoint_count && k < ML_MAX_ENDPOINTS; k++) {
                    if (!cmm_peer->endpoints[k].is_ipv6 &&
                        cmm_peer->endpoints[k].ip == ip && cmm_peer->endpoints[k].port == port) {
                        match = k;
                        break;
                    }
                }
                if (match >= 0) {
                    cmm_peer->endpoints[match].last_ping_ms = 0;  /* force a fresh probe this round */
                } else if (cmm_peer->endpoint_count < ML_MAX_ENDPOINTS) {
                    int slot = cmm_peer->endpoint_count++;
                    cmm_peer->endpoints[slot].ip = ip;
                    cmm_peer->endpoints[slot].port = port;
                    cmm_peer->endpoints[slot].is_ipv6 = false;
                    cmm_peer->endpoints[slot].last_ping_ms = 0;
                }
                /* Table full and genuinely new: dropped, same as real
                 * Tailscale's map would just keep growing but ours can't -
                 * the next MapResponse refresh naturally supersedes this. */
            }

            /* One ping round covers every endpoint just merged above, plus
             * whatever was already known - matches handleCallMeMaybe()
             * calling sendDiscoPingsLocked() exactly once after updating its
             * endpoint map, not once per endpoint. */
            disco_ping_round(ml, peer_idx, true);
        }
        break;
    default:
        ESP_LOGW(TAG, "Unknown DISCO message type: 0x%02x", msg_type);
        break;
    }

    free(plaintext);
    /* pkt->data is freed by the caller */
}

/* ============================================================================
 * WireGuard Packet Processing
 * ========================================================================== */

static void process_wg_packet(microlink_t *ml, const ml_rx_packet_t *pkt) {
    ESP_LOGD(TAG, "WG RX: %d bytes, via_derp=%d, type=%d, from=%02x%02x%02x%02x",
             (int)pkt->len, pkt->via_derp,
             pkt->len >= 4 ? pkt->data[0] : -1,
             pkt->src_pubkey[0], pkt->src_pubkey[1], pkt->src_pubkey[2], pkt->src_pubkey[3]);
    if (!ml->wg_netif) {
        free(pkt->data);
        return;
    }

    struct netif *netif = (struct netif *)ml->wg_netif;
    void *device = netif->state;
    if (!device) {
        free(pkt->data);
        return;
    }

    /* Allocate PBUF_RAM and copy data so the pbuf OWNS its data.
     * This is required because wireguardif decrypts in-place and then
     * calls ip_input → tcpip_input which posts to the TCPIP thread.
     * With PBUF_REF the backing data would be freed before the TCPIP
     * thread processes the packet. */
    struct pbuf *p = pbuf_alloc(PBUF_RAW, pkt->len, PBUF_RAM);
    if (!p) {
        free(pkt->data);
        return;
    }
    pbuf_take(p, pkt->data, pkt->len);
    free(pkt->data);  /* Original data no longer needed — pbuf has its own copy */

    /* Build source address */
    ip_addr_t addr;
    if (pkt->via_derp) {
        ip_addr_set_any(false, &addr);
    } else {
        IP_SET_TYPE_VAL(addr, IPADDR_TYPE_V4);
        ip4_addr_set_u32(ip_2_ip4(&addr), htonl(pkt->src_ip));
    }

    /* Call WG RX handler — pbuf is PBUF_RAM so data survives async delivery */
    wireguardif_network_rx(device, NULL, p, &addr, pkt->src_port);
}

/* ============================================================================
 * SendCallMeMaybe (client-initiated NAT traversal)
 *
 * Sends our local endpoints (LAN + STUN) to a peer via DERP, telling them
 * "connect to me at these addresses". Peer will then initiate WireGuard
 * handshakes to each endpoint, bypassing NAT asymmetry.
 *
 * Reference: tailscale/wgengine/magicsock/magicsock.go (sendCallMeMaybe)
 * ========================================================================== */

static void disco_send_call_me_maybe(microlink_t *ml, int peer_idx) {
    ml_peer_t *p = &ml->peers[peer_idx];

    /* Build plaintext: [type(1)][version(1)][endpoints(N * 18)] */
    uint8_t plaintext[2 + 3 * 18];  /* Up to 3 endpoints */
    int pt_len = 0;
    int ep_count = 0;

    plaintext[pt_len++] = DISCO_MSG_CALL_ME_MAYBE;
    plaintext[pt_len++] = 0;  /* version */

    /* 1. Local LAN IP endpoint (critical for same-network peers) */
    {
        uint32_t local_ip;
        if (ml_lan_ipv4(&local_ip)) {
            uint16_t local_port = ml->disco_local_port;

            if (local_port > 0) {
                /* IPv6-mapped IPv4: ::ffff:A.B.C.D */
                memset(plaintext + pt_len, 0, 10); pt_len += 10;
                plaintext[pt_len++] = 0xff;
                plaintext[pt_len++] = 0xff;
                plaintext[pt_len++] = (local_ip >> 24) & 0xFF;
                plaintext[pt_len++] = (local_ip >> 16) & 0xFF;
                plaintext[pt_len++] = (local_ip >> 8) & 0xFF;
                plaintext[pt_len++] = local_ip & 0xFF;
                plaintext[pt_len++] = (local_port >> 8) & 0xFF;
                plaintext[pt_len++] = local_port & 0xFF;
                ep_count++;

                ESP_LOGD(TAG, "CMM endpoint: LAN %lu.%lu.%lu.%lu:%u",
                         (unsigned long)((local_ip >> 24) & 0xFF),
                         (unsigned long)((local_ip >> 16) & 0xFF),
                         (unsigned long)((local_ip >> 8) & 0xFF),
                         (unsigned long)(local_ip & 0xFF), local_port);
            }
        }
    }

    /* 2. STUN public endpoint (for cross-NAT peers) */
    if (ml->stun_public_ip != 0) {
        uint32_t pub_ip = ml->stun_public_ip;
        uint16_t pub_port = (ml->stun_public_port != 0) ? ml->stun_public_port : ml->disco_local_port;

        memset(plaintext + pt_len, 0, 10); pt_len += 10;
        plaintext[pt_len++] = 0xff;
        plaintext[pt_len++] = 0xff;
        plaintext[pt_len++] = (pub_ip >> 24) & 0xFF;
        plaintext[pt_len++] = (pub_ip >> 16) & 0xFF;
        plaintext[pt_len++] = (pub_ip >> 8) & 0xFF;
        plaintext[pt_len++] = pub_ip & 0xFF;
        plaintext[pt_len++] = (pub_port >> 8) & 0xFF;
        plaintext[pt_len++] = pub_port & 0xFF;
        ep_count++;

        ESP_LOGD(TAG, "CMM endpoint: STUN %lu.%lu.%lu.%lu:%u",
                 (unsigned long)((pub_ip >> 24) & 0xFF),
                 (unsigned long)((pub_ip >> 16) & 0xFF),
                 (unsigned long)((pub_ip >> 8) & 0xFF),
                 (unsigned long)(pub_ip & 0xFF), pub_port);
    }

    if (ep_count == 0) {
        ESP_LOGW(TAG, "CMM: no endpoints available for %s", p->hostname);
        return;
    }

    /* Encrypt with NaCl box */
    uint8_t nonce[DISCO_NONCE_LEN];
    esp_fill_random(nonce, DISCO_NONCE_LEN);

    uint8_t ciphertext[sizeof(plaintext) + NACL_BOX_MACBYTES];
    uint8_t disco_shared[32];
    nacl_box_shared_get(disco_shared, p->disco_key, ml->disco_private_key);
    nacl_box_afternm(ciphertext, plaintext, pt_len, nonce, disco_shared);

    /* Build packet: magic(6) + disco_pubkey(32) + nonce(24) + ciphertext */
    uint8_t pkt[256];
    size_t pos = 0;
    memcpy(pkt + pos, DISCO_MAGIC, 6); pos += 6;
    memcpy(pkt + pos, ml->disco_public_key, 32); pos += 32;
    memcpy(pkt + pos, nonce, DISCO_NONCE_LEN); pos += DISCO_NONCE_LEN;
    size_t ct_len = pt_len + NACL_BOX_MACBYTES;
    memcpy(pkt + pos, ciphertext, ct_len); pos += ct_len;

    /* Send via DERP */
    esp_err_t err = ml_derp_queue_send(ml, p->public_key, pkt, pos);
    if (err == ESP_OK) {
        ESP_LOGD(TAG, "CallMeMaybe sent to %s (%d endpoints)", p->hostname, ep_count);
    } else {
        ESP_LOGW(TAG, "CallMeMaybe send failed for %s: %d", p->hostname, err);
    }
}

/* CallMeMaybe to one peer, for ML_PEER_REQ_HANDSHAKE (wg_mgr task only).
 * Skip on cellular: our endpoints are behind CGNAT and unreachable. */
static void wg_mgr_send_cmm(microlink_t *ml, uint32_t peer_vpn_ip) {
    if (ml_at_socket_is_ready()) return;  /* cellular: CMM useless */
    int idx = find_peer_by_ip(ml, peer_vpn_ip);
    if (idx >= 0) {
        disco_send_call_me_maybe(ml, idx);
    }
}

/* On-demand WG handshake trigger, for ML_PEER_REQ_HANDSHAKE (posted by the
 * TCP/UDP API when a session is needed). wg_mgr task only: it walks peers[]
 * and drives WireGuard handshake state, both owned by this task.
 *
 * Dual-path strategy:
 * 1. DERP: Always send via DERP relay (reliable, works through all NATs)
 * 2. Direct: If DISCO has discovered a direct endpoint, ALSO send the
 *    handshake init directly to the peer's UDP port. This is critical
 *    because the direct path hits magicsock's receiveIPv4() handler which
 *    calls noteRecvActivity() → maybeReconfigWireguardLocked() to re-add
 *    trimmed peers to wireguard-go. The DERP path alone does NOT trigger
 *    this re-add for WG handshake packets, so idle peers silently drop
 *    DERP-only handshake inits.
 *
 * The direct handshake arrives at the peer's magicsock UDP socket, wakes
 * the lazy peer, and wireguard-go processes the init and responds. */
static esp_err_t wg_mgr_trigger_handshake(microlink_t *ml, uint32_t dest_vpn_ip) {
    if (!ml || !ml->wg_netif) return ESP_ERR_INVALID_STATE;

    int idx = find_peer_by_ip(ml, dest_vpn_ip);
    if (idx < 0) return ESP_ERR_NOT_FOUND;

    ml_peer_t *p = &ml->peers[idx];
    if (p->wg_peer_index < 0) return ESP_ERR_INVALID_STATE;

    struct netif *netif = (struct netif *)ml->wg_netif;

    /* Don't destroy an existing valid session */
    err_t is_up = wireguardif_peer_is_up(netif, (u8_t)p->wg_peer_index, NULL, NULL);
    if (is_up == ERR_OK) return ESP_OK;

    /* Path 1: DERP (reliable fallback) */
    wireguardif_connect_derp(netif, (u8_t)p->wg_peer_index);
    ESP_LOGI(TAG, "WG handshake triggered (DERP) to %s", p->hostname);

    /* Path 2: Direct UDP (if DISCO has a known endpoint).
     * This wakes the peer's magicsock via receiveIPv4 → noteRecvActivity.
     * Set connect_ip first, then call wireguardif_connect which copies
     * connect_ip → ip and starts a second handshake to the direct endpoint. */
    if (p->best_ip != 0 && p->best_port != 0) {
        ip_addr_t ep_ip;
        IP_SET_TYPE_VAL(ep_ip, IPADDR_TYPE_V4);
        ip4_addr_set_u32(ip_2_ip4(&ep_ip), htonl(p->best_ip));
        /* Only connect if wireguardif took the address: on ERR_ARG (not a
         * valid underlay endpoint) connect would re-force the previous
         * connect_ip instead. */
        if (wireguardif_update_endpoint(netif, (u8_t)p->wg_peer_index,
                                        &ep_ip, p->best_port) != ERR_OK) {
            return ESP_OK;
        }
        wireguardif_connect(netif, (u8_t)p->wg_peer_index);
        ESP_LOGI(TAG, "WG handshake triggered (direct) to %s at %d.%d.%d.%d:%d",
                 p->hostname,
                 (int)((p->best_ip >> 24) & 0xFF), (int)((p->best_ip >> 16) & 0xFF),
                 (int)((p->best_ip >> 8) & 0xFF), (int)(p->best_ip & 0xFF),
                 (int)p->best_port);
    }

    return ESP_OK;
}

/* Publish which peers have a usable session, for ml_wg_mgr_peer_is_up() on
 * other tasks. wg_mgr only. */
static void wg_publish_session_state(microlink_t *ml) {
    struct netif *netif = (struct netif *)ml->wg_netif;
    for (int i = 0; i < ML_MAX_PEERS; i++) {
        uint32_t up_ip = 0;
        const ml_peer_t *p = &ml->peers[i];
        if (netif && i < ml->peer_count && p->active && p->wg_peer_index >= 0 &&
            wireguardif_peer_is_up(netif, (u8_t)p->wg_peer_index, NULL, NULL) == ERR_OK) {
            up_ip = p->vpn_ip;
        }
        if (__atomic_load_n(&ml->wg_session_up_ip[i], __ATOMIC_RELAXED) != up_ip) {
            __atomic_store_n(&ml->wg_session_up_ip[i], up_ip, __ATOMIC_RELEASE);
        }
    }
}

bool ml_wg_mgr_peer_is_up(microlink_t *ml, uint32_t vpn_ip) {
    if (!ml || vpn_ip == 0) return false;
    for (int i = 0; i < ML_MAX_PEERS; i++) {
        if (__atomic_load_n(&ml->wg_session_up_ip[i], __ATOMIC_ACQUIRE) == vpn_ip) {
            return true;
        }
    }
    return false;
}

void ml_wg_mgr_update_transport(microlink_t *ml) {
#if CONFIG_ML_ENABLE_CELLULAR
    if (!ml || !ml->wg_netif) return;
    struct netif *netif = (struct netif *)ml->wg_netif;
    bool at_ready = ml_at_socket_is_ready();
    wireguardif_force_derp_output(netif, at_ready);
    ESP_LOGI(TAG, "WG transport updated: force_derp=%d (%s)",
             at_ready, at_ready ? "AT socket" : "PPP/WiFi");
#else
    (void)ml;
#endif
}

/* ============================================================================
 * Periodic DISCO probing (rate-limited per tailscaled timing)
 * ========================================================================== */

/* Max upgrade probes per call to spread DISCO load across ticks.
 * With 16 allowed peers: full probe cycle = 8 ticks × 1s = 8s,
 * well within the 15s upgrade interval. */
#define DISCO_PROBES_PER_TICK 2

static int disco_probe_start_idx = 0;

static void disco_periodic_probes(microlink_t *ml) {
    uint64_t now = ml_get_time_ms();
    int upgrade_probes_sent = 0;

    /* Rotate start index so we don't always process peers in the same order */
    int start = disco_probe_start_idx;
    if (start >= ml->peer_count) start = 0;

    for (int n = 0; n < ml->peer_count; n++) {
        int i = (start + n) % ml->peer_count;
        ml_peer_t *p = &ml->peers[i];
        if (!p->active) continue;

        /* Peer allowlist filter: check early so we can skip expensive work.
         * Inbound DISCO pings from any peer are still answered (don't break remote). */
        bool peer_allowed = ml_config_peer_is_allowed(
            ml->config_httpd, p->vpn_ip);

        /* Check if direct path trust has expired (always runs, not throttled) */
        if (p->has_direct_path && now > p->trust_until_ms) {
            ESP_LOGI(TAG, "Direct path to %s expired, reverting to DERP", p->hostname);
            p->has_direct_path = false;

            /* Only do DERP fallback + re-probe for allowed peers.
             * Non-allowed peers just get their state cleaned above. */
            if (peer_allowed) {
                /* Re-initiate DERP handshake only if we have an active WG session. */
                if (ml->wg_netif && p->wg_peer_index >= 0) {
                    struct netif *netif = (struct netif *)ml->wg_netif;
                    err_t is_up = wireguardif_peer_is_up(netif, (u8_t)p->wg_peer_index,
                                                           NULL, NULL);
                    if (is_up == ERR_OK) {
                        wireguardif_connect_derp(netif, (u8_t)p->wg_peer_index);
                        ESP_LOGI(TAG, "  WG session active, falling back to DERP for %s", p->hostname);
                    }
                }

                /* Force-ping to try re-establishing direct path (WiFi only) */
                if (!ml_at_socket_is_ready()) {
                    disco_ping_round(ml, i, true);
                }
            }
        }

        if (!peer_allowed) continue;

        /* Probe for direct path upgrade (every UPGRADE_INTERVAL when on DERP).
         * Skip on cellular: direct paths impossible through carrier-grade NAT.
         * Throttled to DISCO_PROBES_PER_TICK to spread load and reduce jitter. */
        if (!ml_at_socket_is_ready() && !p->has_direct_path &&
            now - p->last_upgrade_ms > ML_DISCO_UPGRADE_INTERVAL_MS) {
            if (upgrade_probes_sent < DISCO_PROBES_PER_TICK) {
                disco_ping_round(ml, i, false);
                p->last_upgrade_ms = now;
                upgrade_probes_sent++;
            }
        }

        /* Heartbeat on active direct paths (every HEARTBEAT interval).
         * Only the best path is pinged; a full round (force=true, because
         * HEARTBEAT_MS (3s) < PING_INTERVAL_MS (5s) and the per-endpoint
         * rate limiter would block it) runs every DISCO_FULL_PING_INTERVAL_MS
         * to look for a better path, and as soon as the best path misses a
         * heartbeat so another one can take over before trust expires.
         * Heartbeats are NEVER throttled — they're time-critical for trust_until_ms. */
        if (p->has_direct_path &&
            now - p->last_ping_sent_ms > ml->t_disco_heartbeat_ms) {
            bool best_shaky = now - p->best_pong_ms > 2 * (uint64_t)ml->t_disco_heartbeat_ms;
            if (best_shaky || now - p->last_full_ping_ms >= DISCO_FULL_PING_INTERVAL_MS) {
                disco_ping_round(ml, i, true);
            } else {
                disco_ping_best(ml, i);
            }
        }
    }

    /* Advance rotating start index for next call */
    disco_probe_start_idx = (start + DISCO_PROBES_PER_TICK) % (ml->peer_count > 0 ? ml->peer_count : 1);

    /* Expire old pending probes.
     * MUST refresh 'now' because disco_ping_round() above may have
     * registered probes with sent_ms NEWER than our stale 'now' from the top
     * of this function. Without refresh, now - sent_ms underflows to ~UINT64_MAX
     * which is always > PING_TIMEOUT_MS, causing immediate false expiry. */
    now = ml_get_time_ms();
    for (int i = 0; i < MAX_PENDING_PROBES; i++) {
        if (pending_probes[i].active &&
            now - pending_probes[i].sent_ms > ML_DISCO_PING_TIMEOUT_MS) {
            pending_probes[i].active = false;
        }
    }
}

/* ============================================================================
 * WG Manager Task
 * ========================================================================== */

void ml_wg_mgr_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "WG Manager task started (Core %d)", xPortGetCoreID());

    /* Initialize probe tracking (module statics survive a stop/start) */
    memset(pending_probes, 0, sizeof(pending_probes));
    s_disco_round = 0;
    disco_probe_start_idx = 0;

    /* Load cached peers from NVS for fast boot */
    int cached = ml_peer_nvs_load_all(ml->peers, ML_MAX_PEERS);
    if (cached > 0) {
        ml->peer_count = cached;
        ESP_LOGI(TAG, "Pre-loaded %d cached peers from NVS", cached);
    }

    /* Wait for registration OR shutdown before proceeding */
    EventBits_t wait_bits = xEventGroupWaitBits(ml->events,
                         ML_EVT_COORD_REGISTERED | ML_EVT_SHUTDOWN_REQUEST,
                         pdFALSE, pdFALSE, portMAX_DELAY);

    if (wait_bits & ML_EVT_SHUTDOWN_REQUEST) {
        ESP_LOGI(TAG, "Shutdown requested before registration, exiting");
        ml_task_exit(ml, ML_TASK_BIT_WG_MGR);
    }

    ESP_LOGI(TAG, "Coord registered, initializing WireGuard...");

    /* Initialize WireGuard interface (magicsock mode) */
    if (wg_init_interface(ml) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init WireGuard, continuing without tunneling");
    } else {
        /* Update VPN IP if coord already set it */
        wg_update_vpn_ip(ml);
        xEventGroupSetBits(ml->events, ML_EVT_WG_READY);
    }

    ESP_LOGI(TAG, "Accepting peer updates");

    uint64_t last_disco_probe_ms = 0;
    uint64_t last_wg_periodic_ms = 0;
    uint64_t last_session_publish_ms = 0;
    bool derp_was_connected = false;
    bool stun_cmm_sent = false;  /* One-shot: send CMMs after first STUN result */

    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {
        /* Process peer updates from coord task (and app-side requests) */
        process_peer_updates(ml);
        cmm_sweep_step(ml);

        /* Track DERP connection state for DISCO.
         * Note: We DON'T re-initiate WG handshakes on DERP connect because
         * Tailscale peers use lazy config and would drop our initiations.
         * WG sessions are established on-demand when peers initiate to us. */
        {
            EventBits_t bits = xEventGroupGetBits(ml->events);
            bool derp_connected_now = (bits & ML_EVT_DERP_CONNECTED) != 0;
            if (derp_connected_now && !derp_was_connected) {
                ESP_LOGI(TAG, "DERP connected, %d peers ready for incoming handshakes",
                         ml->peer_count);
            }
            derp_was_connected = derp_connected_now;
        }

        /* After STUN completes, broadcast CallMeMaybe to all peers.
         * Peers need to know our public endpoint (from STUN) to send direct
         * probes. Without this, our initial CMMs during peer-add have 0
         * endpoints because STUN hasn't finished yet. */
        if (!stun_cmm_sent && !ml_at_socket_is_ready() &&
            ml->stun_public_ip != 0 && ml->peer_count > 0) {
            stun_cmm_sent = true;
            int cmm_count = 0;
            for (int i = 0; i < ml->peer_count; i++) {
                if (!ml->peers[i].active) continue;
                if (ml->peers[i].has_direct_path) continue;
                disco_send_call_me_maybe(ml, i);
                cmm_count++;
            }
            ESP_LOGI(TAG, "STUN complete — sent CallMeMaybe to %d peers", cmm_count);
        }

        /* Process DISCO packets */
#ifdef CONFIG_ML_ZERO_COPY_WG
        /* Zero-copy mode: drain SPSC ring buffer (PCB callback → wg_mgr) */
        {
            uint8_t tail = __atomic_load_n(&ml->zc.rx_tail, __ATOMIC_RELAXED);
            uint8_t head = __atomic_load_n(&ml->zc.rx_head, __ATOMIC_ACQUIRE);
            while (tail != head) {
                ml_zc_disco_entry_t *entry = &ml->zc.rx_ring[tail];
                ml_rx_packet_t disco_pkt = {
                    .data = entry->data,
                    .len = entry->len,
                    .src_ip = ntohl(entry->src_ip_nbo),
                    .src_port = entry->src_port,
                    .via_derp = false,
                };
                process_disco_packet(ml, &disco_pkt);
                /* Don't free — data is in the ring buffer, not heap-allocated */
                tail = (tail + 1) % ML_ZC_DISCO_RING_SIZE;
                head = __atomic_load_n(&ml->zc.rx_head, __ATOMIC_ACQUIRE);
            }
            __atomic_store_n(&ml->zc.rx_tail, tail, __ATOMIC_RELEASE);
        }
#endif
        /* Queue-based path: DISCO from DERP relay + fallback when zero-copy disabled */
        ml_rx_packet_t disco_pkt;
        while (xQueueReceive(ml->disco_rx_queue, &disco_pkt, 0) == pdTRUE) {
            process_disco_packet(ml, &disco_pkt);
            free(disco_pkt.data);
        }

        /* Idle wait: block until a producer signals work (WG/DISCO packet,
         * peer update or request; see ml_wg_mgr_wake) or the periodic tick.
         * This replaces a fixed 10 ms poll (100 wakeups/s while idle). A give
         * between the emptiness check and the take is not lost: the binary
         * semaphore stays given. */
        if (uxQueueMessagesWaiting(ml->wg_rx_queue) == 0 &&
            uxQueueMessagesWaiting(ml->disco_rx_queue) == 0 &&
            uxQueueMessagesWaiting(ml->peer_update_queue) == 0
#ifdef CONFIG_ML_ZERO_COPY_WG
            && __atomic_load_n(&ml->zc.rx_tail, __ATOMIC_RELAXED) ==
               __atomic_load_n(&ml->zc.rx_head, __ATOMIC_ACQUIRE)
#endif
            ) {
            xSemaphoreTake(ml->wg_wake, pdMS_TO_TICKS(ML_WG_IDLE_TICK_MS));
        }

        /* Process WireGuard packets */
        ml_rx_packet_t wg_pkt;
        bool wg_rx = false;
        if (xQueueReceive(ml->wg_rx_queue, &wg_pkt, 0) == pdTRUE) {
            wg_rx = true;
            process_wg_packet(ml, &wg_pkt);
            while (xQueueReceive(ml->wg_rx_queue, &wg_pkt, 0) == pdTRUE) {
                process_wg_packet(ml, &wg_pkt);
            }
        }

        /* Run WireGuard periodic processing (handshakes, keepalives, rekeys).
         * This runs on OUR task stack (8KB) instead of the lwIP TCPIP thread (3-8KB),
         * preventing heavy crypto (X25519, ChaCha20-Poly1305) from monopolizing
         * the TCPIP thread and blocking all socket operations system-wide. */
        uint64_t now = ml_get_time_ms();
        if (wg_rx || now - last_session_publish_ms >= 100) {
            wg_publish_session_state(ml);
            last_session_publish_ms = now;
        }
        if (ml->wg_netif && now - last_wg_periodic_ms >= 400) {
            uint64_t t0 = now;
            wireguardif_periodic((struct netif *)ml->wg_netif);
            uint64_t dt = ml_get_time_ms() - t0;
            last_wg_periodic_ms = now;
            ESP_LOGD(TAG, "wireguardif_periodic: %lu ms", (unsigned long)dt);
        }

        /* Periodic DISCO probes (every 1s check) */
        now = ml_get_time_ms();
        if (now - last_disco_probe_ms > 1000) {
            uint64_t t0 = now;
            disco_periodic_probes(ml);
            uint64_t dt = ml_get_time_ms() - t0;
            last_disco_probe_ms = now;
            ESP_LOGD(TAG, "disco_periodic_probes: %lu ms", (unsigned long)dt);
        }

        /* No trailing delay: the blocking receive above paces the loop and
         * yields whenever there is nothing to do. */
    }

    /* Shutdown WireGuard interface */
    wg_teardown_interface(ml);
    for (int i = 0; i < ML_MAX_PEERS; i++) {
        __atomic_store_n(&ml->wg_session_up_ip[i], 0, __ATOMIC_RELEASE);
    }
    /* wg_mgr is the only DISCO user: drop the cached shared keys and the
     * cache's copy of our disco private key, which would otherwise outlive
     * microlink_destroy() in static RAM. */
    nacl_box_shared_cache_wipe();

    ESP_LOGI(TAG, "WG Manager task exiting");
    ml_task_exit(ml, ML_TASK_BIT_WG_MGR);
}
