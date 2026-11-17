/*
 * ml_nat66: IPv6 masquerading for an exit node. See ml_nat66.h.
 */
#include "ml_nat66.h"
#include <string.h>

#define NH_TCP    6
#define NH_UDP    17
#define NH_ICMP6  58
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY   129

#define TIMEOUT_TCP_MS  (2u * 60u * 60u * 1000u)   /* idle established TCP */
#define TIMEOUT_UDP_MS  (120u * 1000u)
#define TIMEOUT_ICMP_MS (30u * 1000u)

typedef struct {
    uint8_t  client[16];   /* peer's tailnet address */
    uint8_t  lan[16];      /* our address it was mapped to */
    uint16_t cport;        /* peer's port / echo identifier */
    uint16_t mport;        /* mapped port / identifier */
    uint32_t ts;
    uint8_t  proto;
    bool     used;
} slot_t;

static slot_t   s_slots[ML_NAT66_SLOTS];
static uint16_t s_next = ML_NAT66_PORT_LO;

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

/* RFC 1624 incremental update of a ones'-complement checksum for a change
 * of n (even) bytes from old to new. */
static void csum_replace(uint8_t *csum, const uint8_t *old, const uint8_t *new, size_t n) {
    uint32_t sum = (uint16_t)~rd16(csum);
    for (size_t i = 0; i < n; i += 2) {
        sum += (uint16_t)~rd16(old + i);
        sum += rd16(new + i);
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    wr16(csum, (uint16_t)~sum);
}

static uint32_t timeout_of(uint8_t proto) {
    return proto == NH_TCP ? TIMEOUT_TCP_MS : proto == NH_UDP ? TIMEOUT_UDP_MS : TIMEOUT_ICMP_MS;
}

static bool live(const slot_t *s, uint32_t now) {
    return s->used && (uint32_t)(now - s->ts) < timeout_of(s->proto);
}

/* Where the port (or echo identifier) and checksum of a packet are, for the
 * given direction. Returns false for what is not translated. */
static bool locate(uint8_t *pkt, size_t len, bool outbound, uint8_t *proto,
                   size_t *port_off, size_t *csum_off) {
    if (len < 40 || (pkt[0] >> 4) != 6) return false;
    *proto = pkt[6];
    switch (*proto) {
    case NH_TCP:
        if (len < 40 + 18) return false;
        *port_off = outbound ? 40 : 42;
        *csum_off = 40 + 16;
        return true;
    case NH_UDP:
        if (len < 40 + 8 || rd16(pkt + 40 + 6) == 0) return false;   /* checksum is mandatory in IPv6 */
        *port_off = outbound ? 40 : 42;
        *csum_off = 40 + 6;
        return true;
    case NH_ICMP6:
        if (len < 40 + 8) return false;
        if (pkt[40] != (outbound ? ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY)) return false;
        *port_off = 40 + 4;   /* identifier */
        *csum_off = 40 + 2;
        return true;
    default:
        return false;
    }
}

static bool mport_free(uint8_t proto, uint16_t port, uint32_t now) {
    for (int i = 0; i < ML_NAT66_SLOTS; i++) {
        if (live(&s_slots[i], now) && s_slots[i].proto == proto && s_slots[i].mport == port) return false;
    }
    return true;
}

static slot_t *slot_for(uint8_t proto, const uint8_t client[16], uint16_t cport,
                        const uint8_t lan[16], uint32_t now) {
    slot_t *free_slot = NULL, *oldest = NULL;
    for (int i = 0; i < ML_NAT66_SLOTS; i++) {
        slot_t *s = &s_slots[i];
        if (live(s, now)) {
            if (s->proto == proto && s->cport == cport && memcmp(s->client, client, 16) == 0 &&
                memcmp(s->lan, lan, 16) == 0) {
                return s;
            }
            if (!oldest || (uint32_t)(now - s->ts) > (uint32_t)(now - oldest->ts)) oldest = s;
        } else if (!free_slot) {
            free_slot = s;
        }
    }
    slot_t *s = free_slot ? free_slot : oldest;   /* table full: reuse the least recently used */
    if (!s) return NULL;
    s->used = false;

    /* Keep the peer's port when it is in our range and free, else take the next free one. */
    uint16_t port = 0;
    if (cport >= ML_NAT66_PORT_LO && cport <= ML_NAT66_PORT_HI && mport_free(proto, cport, now)) {
        port = cport;
    } else {
        for (int tries = 0; tries <= ML_NAT66_PORT_HI - ML_NAT66_PORT_LO; tries++) {
            uint16_t p = s_next;
            s_next = (uint16_t)(s_next >= ML_NAT66_PORT_HI ? ML_NAT66_PORT_LO : s_next + 1);
            if (mport_free(proto, p, now)) { port = p; break; }
        }
    }
    if (!port) return NULL;
    s->proto = proto;
    memcpy(s->client, client, 16);
    memcpy(s->lan, lan, 16);
    s->cport = cport;
    s->mport = port;
    s->used = true;
    s->ts = now;
    return s;
}

void ml_nat66_reset(void) {
    memset(s_slots, 0, sizeof(s_slots));
    s_next = ML_NAT66_PORT_LO;
}

int ml_nat66_out(uint8_t *pkt, size_t len, const uint8_t lan_addr[16], uint32_t now) {
    uint8_t proto;
    size_t port_off, csum_off;
    if (!locate(pkt, len, true, &proto, &port_off, &csum_off)) return -1;
    uint8_t *src = pkt + 8;
    uint16_t cport = rd16(pkt + port_off);
    slot_t *s = slot_for(proto, src, cport, lan_addr, now);
    if (!s) return -1;
    s->ts = now;

    uint8_t newport[2];
    wr16(newport, s->mport);
    /* TCP, UDP and ICMPv6 checksums all cover the pseudo-header's addresses */
    csum_replace(pkt + csum_off, src, lan_addr, 16);
    csum_replace(pkt + csum_off, pkt + port_off, newport, 2);
    memcpy(src, lan_addr, 16);
    memcpy(pkt + port_off, newport, 2);
    return 0;
}

int ml_nat66_in(uint8_t *pkt, size_t len, uint32_t now) {
    uint8_t proto;
    size_t port_off, csum_off;
    if (!locate(pkt, len, false, &proto, &port_off, &csum_off)) return 0;
    uint8_t *dst = pkt + 24;
    uint16_t mport = rd16(pkt + port_off);
    if (mport < ML_NAT66_PORT_LO || mport > ML_NAT66_PORT_HI) return 0;
    for (int i = 0; i < ML_NAT66_SLOTS; i++) {
        slot_t *s = &s_slots[i];
        if (!live(s, now) || s->proto != proto || s->mport != mport || memcmp(s->lan, dst, 16) != 0) continue;
        s->ts = now;
        uint8_t oldport[2];
        memcpy(oldport, pkt + port_off, 2);
        uint8_t newport[2];
        wr16(newport, s->cport);
        csum_replace(pkt + csum_off, dst, s->client, 16);
        csum_replace(pkt + csum_off, oldport, newport, 2);
        memcpy(dst, s->client, 16);
        memcpy(pkt + port_off, newport, 2);
        return 1;
    }
    return 0;
}

/* 3 global (and anything else routable), 2 unique local, 1 link-local */
static int scope6(const uint8_t a[16]) {
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return 1;
    if ((a[0] & 0xfe) == 0xfc) return 2;
    return 3;
}

bool ml_nat66_source_ok(const uint8_t src[16], const uint8_t dst[16]) {
    static const uint8_t zero[16] = { 0 };
    if (memcmp(src, zero, 16) == 0 || src[0] == 0xff) return false;
    int s = scope6(src);
    return s >= 2 && s >= scope6(dst);
}

/* Full ICMPv6 checksum over the pseudo-header and message. */
static uint16_t icmp6_checksum(const uint8_t *pkt, size_t len) {
    uint32_t sum = 0;
    for (int i = 8; i < 40; i += 2) sum += rd16(pkt + i);
    uint32_t plen = (uint32_t)(len - 40);
    sum += (plen >> 16) + (plen & 0xFFFF) + NH_ICMP6;
    for (size_t i = 40; i < len; i += 2) sum += (uint32_t)(pkt[i] << 8 | (i + 1 < len ? pkt[i + 1] : 0));
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

size_t ml_nat66_unreachable(const uint8_t *pkt, size_t len, const uint8_t from[16],
                            uint8_t *out, size_t out_max) {
    if (len < 40 || (pkt[0] >> 4) != 6) return 0;
    if (pkt[6] == NH_ICMP6 && (len < 41 || pkt[40] < 128)) return 0;   /* never answer an error */
    size_t quote = len;
    if (quote > 1280 - 48) quote = 1280 - 48;
    size_t n = 48 + quote;
    if (n > out_max) return 0;
    memset(out, 0, 48);
    out[0] = 0x60;
    wr16(out + 4, (uint16_t)(n - 40));
    out[6] = NH_ICMP6;
    out[7] = 64;
    memcpy(out + 8, from, 16);
    memcpy(out + 24, pkt + 8, 16);           /* back to the sender */
    out[40] = 1;                             /* Destination Unreachable */
    out[41] = 0;                             /* no route to destination */
    memcpy(out + 48, pkt, quote);
    wr16(out + 42, icmp6_checksum(out, n));
    return n;
}

int ml_nat66_count(uint32_t now) {
    int n = 0;
    for (int i = 0; i < ML_NAT66_SLOTS; i++) n += live(&s_slots[i], now);
    return n;
}

/* ------------------------------------------------------------------------ */
/* lwIP glue                                                                */

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif

#if defined(ESP_PLATFORM) && defined(CONFIG_ML_ROUTER_IPV6)
#include "lwip/ip6.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"

static struct netif *s_wg;
static uint8_t s_self6[16];
static uint8_t s_icmp_buf[1280];         /* tcpip_thread only */
static uint32_t s_icmp_window_ms;
static int s_icmp_in_window;

void ml_nat66_attach(struct netif *wg_netif, const uint8_t self6[16]) {
    s_wg = wg_netif;
    if (self6) memcpy(s_self6, self6, 16);
    ml_nat66_reset();
}

/* Applications that need lwIP's IPv6 input hook themselves define this
 * instead of lwip_hook_ip6_input() (which MicroLink provides); it sees every
 * packet MicroLink did not consume, after translation. */
int __attribute__((weak)) microlink_ip6_input_hook(struct pbuf *p, struct netif *inp) {
    (void)p;
    (void)inp;
    return 0;
}

/* Answer a packet we cannot forward with ICMPv6 "no route", so the peer's
 * stack fails at once (and falls back to IPv4) instead of timing out.
 * At most 10 per second. */
static void send_no_route(struct netif *wg, const uint8_t *pkt, size_t len) {
    uint32_t now = sys_now();
    if ((uint32_t)(now - s_icmp_window_ms) >= 1000) {
        s_icmp_window_ms = now;
        s_icmp_in_window = 0;
    }
    if (++s_icmp_in_window > 10) return;
    size_t n = ml_nat66_unreachable(pkt, len, s_self6, s_icmp_buf, sizeof(s_icmp_buf));
    if (!n) return;
    struct pbuf *q = pbuf_alloc(PBUF_RAW, (u16_t)n, PBUF_RAM);
    if (!q) return;
    memcpy(q->payload, s_icmp_buf, n);
    ip6_addr_t dst;
    memset(&dst, 0, sizeof(dst));
    memcpy(dst.addr, s_icmp_buf + 24, 16);
    wg->output_ip6(wg, q, &dst);
    pbuf_free(q);
}

/* Same rule as the packet filter's: not the tailnet range, link-local,
 * multicast, loopback or unspecified. */
static bool forwardable(const uint8_t a[16]) {
    static const uint8_t tailnet[6] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 };
    static const uint8_t zero[15] = { 0 };
    if (memcmp(a, tailnet, 6) == 0) return false;
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return false;
    if (a[0] == 0xff) return false;
    if (memcmp(a, zero, 15) == 0 && a[15] <= 1) return false;
    return true;
}

/* LWIP_HOOK_IP6_INPUT: called by ip6_input() on tcpip_thread for every
 * IPv6 packet, before the destination is looked at. Returns 1 if the packet
 * was consumed (freed). A translated packet goes on through ip6_input, which
 * forwards it (CONFIG_LWIP_IPV6_FORWARD): out of the LAN interface, or back
 * into the tunnel. */
int lwip_hook_ip6_input(struct pbuf *p, struct netif *inp) {
    struct netif *wg = s_wg;
    if (!wg || !p || p->len < 40) return microlink_ip6_input_hook(p, inp);
    uint8_t *pkt = (uint8_t *)p->payload;
    uint32_t now = sys_now();

    if (inp == wg) {
        if (forwardable(pkt + 24)) {
            /* The packet filter already checked that we forward to this
             * destination (exit node, or an advertised IPv6 route). */
            ip6_addr_t dst;
            memset(&dst, 0, sizeof(dst));
            memcpy(dst.addr, pkt + 24, 16);
            /* lwIP falls back to the default interface and to a link-local
             * source when there is nothing better: forwarding then would
             * only lose the packet on the LAN. Require a LAN address whose
             * scope reaches the destination, else answer "no route". */
            struct netif *out = ip6_route(IP6_ADDR_ANY6, &dst);
            const ip_addr_t *src = (out && out != wg) ? ip6_select_source_address(out, &dst) : NULL;
            if (!src || !ml_nat66_source_ok((const uint8_t *)ip_2_ip6(src)->addr, pkt + 24)) {
                send_no_route(wg, pkt, p->len);
                pbuf_free(p);
                return 1;
            }
            if (ml_nat66_out(pkt, p->len, (const uint8_t *)ip_2_ip6(src)->addr, now) != 0) {
                pbuf_free(p);                   /* not translatable: never leak a tailnet source */
                return 1;
            }
        }
    } else {
        ml_nat66_in(pkt, p->len, now);
    }
    return microlink_ip6_input_hook(p, inp);
}
#endif
