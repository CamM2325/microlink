/*
 * ml_filter: on-device enforcement of the tailnet packet filter.
 * See ml_filter.h for semantics. IPv4 only (MicroLink's tunnel is IPv4).
 */
#include "ml_filter.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
static const char *TAG = "ml_filter";
static SemaphoreHandle_t s_lock;
#define F_LOCK()   do { if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY); } while (0)
#define F_UNLOCK() do { if (s_lock) xSemaphoreGive(s_lock); } while (0)
#define F_LOGW(...) ESP_LOGW(TAG, __VA_ARGS__)
#define F_LOGI(...) ESP_LOGI(TAG, __VA_ARGS__)
#define F_LOGD(...) ESP_LOGD(TAG, __VA_ARGS__)
#else
#define F_LOCK()   do { } while (0)
#define F_UNLOCK() do { } while (0)
#define F_LOGW(...) do { } while (0)
#define F_LOGI(...) do { } while (0)
#define F_LOGD(...) do { } while (0)
#endif

#ifdef CONFIG_ML_FILTER_MAX_ENTRIES
#define MAX_ENTRIES CONFIG_ML_FILTER_MAX_ENTRIES
#else
#define MAX_ENTRIES 4096        /* src + dst entries per named set */
#endif
#define MAX_SETS        8
#define MAX_PROTOS      8
#define FLOW_SLOTS      64
#define FLOW_TIMEOUT_MS 120000u

#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP   17
#define PROTO_SCTP  132

typedef struct { uint32_t lo, hi; } range_t;                    /* host order, inclusive */
typedef struct { range_t ip; uint16_t port_lo, port_hi; } dst_t;
typedef struct {
    uint32_t src_first, src_count, dst_first, dst_count;
    uint8_t  protos[MAX_PROTOS];
    uint8_t  nprotos;                                          /* 0 = default set */
} rule_t;
typedef struct {
    rule_t  *rules;  uint32_t nrules;
    range_t *src;    uint32_t nsrc;
    dst_t   *dst;    uint32_t ndst;
} policy_t;
typedef struct { char name[24]; policy_t *pol; } set_t;
typedef struct {
    uint32_t peer_ip, local_ip, ts;
    uint16_t peer_port, local_port;
    bool     used;
} flow_t;

static ml_filter_mode_t s_mode = ML_FILTER_MODE_OFF;
static set_t   s_sets[MAX_SETS];
static bool    s_configured;
static flow_t  s_flows[FLOW_SLOTS];
static ml_filter_stats_t s_stats;
static uint32_t   s_self_ip;                    /* 0 = not known yet */
static ml_route_t s_local_routes[ML_MAX_ROUTES];
static int        s_nlocal_routes;

/* ------------------------------------------------------------------------ */

static bool parse_ip4(const char *s, const char *end, uint32_t *out) {
    uint32_t v = 0;
    int parts = 0;
    while (s < end && parts < 4) {
        if (*s < '0' || *s > '9') return false;
        uint32_t oct = 0;
        int digits = 0;
        while (s < end && *s >= '0' && *s <= '9') {
            oct = oct * 10 + (uint32_t)(*s - '0');
            if (++digits > 3 || oct > 255) return false;
            s++;
        }
        v = (v << 8) | oct;
        parts++;
        if (parts < 4) {
            if (s >= end || *s != '.') return false;
            s++;
        }
    }
    if (parts != 4 || s != end) return false;
    *out = v;
    return true;
}

/* "*", "a.b.c.d", "a.b.c.d/n", "a.b.c.d-e.f.g.h". Returns false for anything
 * else, including IPv6 (skipped: the tunnel is IPv4-only). */
static bool parse_range(const char *str, range_t *r) {
    if (!str) return false;
    if (strcmp(str, "*") == 0) { r->lo = 0; r->hi = 0xFFFFFFFFu; return true; }
    if (strchr(str, ':')) return false;
    const char *end = str + strlen(str);
    const char *slash = strchr(str, '/');
    const char *dash = strchr(str, '-');
    uint32_t a, b;
    if (slash) {
        if (!parse_ip4(str, slash, &a)) return false;
        const char *p = slash + 1;
        if (p >= end || end - p > 2) return false;
        int bits = 0;
        for (; p < end; p++) {
            if (*p < '0' || *p > '9') return false;
            bits = bits * 10 + (*p - '0');
        }
        if (bits > 32) return false;
        uint32_t mask = bits ? (0xFFFFFFFFu << (32 - bits)) : 0;
        r->lo = a & mask;
        r->hi = r->lo | ~mask;
        return true;
    }
    if (dash) {
        if (!parse_ip4(str, dash, &a) || !parse_ip4(dash + 1, end, &b) || b < a) return false;
        r->lo = a; r->hi = b;
        return true;
    }
    if (!parse_ip4(str, end, &a)) return false;
    r->lo = r->hi = a;
    return true;
}

static void policy_free(policy_t *p) {
    if (!p) return;
    free(p->rules);
    free(p->src);
    free(p->dst);
    free(p);
}

/* A rule grants packet access only if it has DstPorts (CapGrant-only rules
 * grant application capabilities, not packets). */
static bool rule_is_packet_rule(const cJSON *r) {
    const cJSON *dp = cJSON_GetObjectItemCaseSensitive(r, "DstPorts");
    return cJSON_IsArray(dp) && cJSON_GetArraySize(dp) > 0;
}

/* Two passes: count, then fill. Returns NULL on error/limit (rules == NULL
 * or an empty array yields a valid empty policy = deny all). */
static policy_t *policy_parse(const cJSON *rules) {
    if (!cJSON_IsArray(rules)) return NULL;
    uint32_t nrules = 0, nsrc = 0, ndst = 0;
    const cJSON *r;
    cJSON_ArrayForEach(r, rules) {
        if (!cJSON_IsObject(r) || !rule_is_packet_rule(r)) continue;
        nrules++;
        const cJSON *e;
        range_t tmp;
        cJSON_ArrayForEach(e, cJSON_GetObjectItemCaseSensitive(r, "SrcIPs")) {
            if (cJSON_IsString(e) && parse_range(e->valuestring, &tmp)) nsrc++;
        }
        cJSON_ArrayForEach(e, cJSON_GetObjectItemCaseSensitive(r, "DstPorts")) {
            const cJSON *ip = cJSON_GetObjectItemCaseSensitive(e, "IP");
            if (cJSON_IsString(ip) && parse_range(ip->valuestring, &tmp)) ndst++;
        }
        if (nsrc + ndst > MAX_ENTRIES) return NULL;
    }
    policy_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->rules = calloc(nrules ? nrules : 1, sizeof(rule_t));
    p->src = calloc(nsrc ? nsrc : 1, sizeof(range_t));
    p->dst = calloc(ndst ? ndst : 1, sizeof(dst_t));
    if (!p->rules || !p->src || !p->dst) { policy_free(p); return NULL; }

    cJSON_ArrayForEach(r, rules) {
        if (!cJSON_IsObject(r) || !rule_is_packet_rule(r)) continue;
        rule_t *rule = &p->rules[p->nrules];
        rule->src_first = p->nsrc;
        rule->dst_first = p->ndst;
        const cJSON *e;
        cJSON_ArrayForEach(e, cJSON_GetObjectItemCaseSensitive(r, "SrcIPs")) {
            if (cJSON_IsString(e) && p->nsrc < nsrc && parse_range(e->valuestring, &p->src[p->nsrc])) p->nsrc++;
        }
        cJSON_ArrayForEach(e, cJSON_GetObjectItemCaseSensitive(r, "DstPorts")) {
            const cJSON *ip = cJSON_GetObjectItemCaseSensitive(e, "IP");
            if (!cJSON_IsString(ip) || p->ndst >= ndst || !parse_range(ip->valuestring, &p->dst[p->ndst].ip)) continue;
            uint16_t lo = 0, hi = 65535;
            const cJSON *ports = cJSON_GetObjectItemCaseSensitive(e, "Ports");
            if (cJSON_IsObject(ports)) {
                const cJSON *f = cJSON_GetObjectItemCaseSensitive(ports, "First");
                const cJSON *l = cJSON_GetObjectItemCaseSensitive(ports, "Last");
                double fv = cJSON_IsNumber(f) ? f->valuedouble : 0;
                double lv = cJSON_IsNumber(l) ? l->valuedouble : 65535;
                if (fv < 0) fv = 0;
                if (lv > 65535) lv = 65535;
                if (lv < fv) continue;               /* empty range: matches nothing */
                lo = (uint16_t)fv; hi = (uint16_t)lv;
            }
            p->dst[p->ndst].port_lo = lo;
            p->dst[p->ndst].port_hi = hi;
            p->ndst++;
        }
        rule->src_count = p->nsrc - rule->src_first;
        rule->dst_count = p->ndst - rule->dst_first;
        cJSON_ArrayForEach(e, cJSON_GetObjectItemCaseSensitive(r, "IPProto")) {
            if (cJSON_IsNumber(e) && e->valuedouble >= 0 && e->valuedouble <= 255 &&
                rule->nprotos < MAX_PROTOS) {
                rule->protos[rule->nprotos++] = (uint8_t)e->valuedouble;
            }
        }
        p->nrules++;
    }
    return p;
}

static set_t *set_find(const char *name, bool create) {
    set_t *free_slot = NULL;
    for (int i = 0; i < MAX_SETS; i++) {
        if (s_sets[i].pol || s_sets[i].name[0]) {
            if (strcmp(s_sets[i].name, name) == 0) return &s_sets[i];
        } else if (!free_slot) {
            free_slot = &s_sets[i];
        }
    }
    if (create && free_slot) {
        strncpy(free_slot->name, name, sizeof(free_slot->name) - 1);
        free_slot->name[sizeof(free_slot->name) - 1] = '\0';
        return free_slot;
    }
    return NULL;
}

/* Replace (or with pol == NULL, delete) a named set. Caller holds the lock. */
static void set_replace_locked(const char *name, policy_t *pol) {
    set_t *s = set_find(name, pol != NULL);
    if (!s) { policy_free(pol); return; }
    policy_free(s->pol);
    s->pol = pol;
    if (!pol) memset(s, 0, sizeof(*s));
}

static uint32_t count_rules_locked(void) {
    uint32_t n = 0;
    for (int i = 0; i < MAX_SETS; i++) if (s_sets[i].pol) n += s_sets[i].pol->nrules;
    return n;
}

/* ------------------------------------------------------------------------ */

void ml_filter_init(ml_filter_mode_t mode) {
#ifdef ESP_PLATFORM
    if (!s_lock) s_lock = xSemaphoreCreateMutex();
#endif
    s_mode = mode;
}

void ml_filter_reset(void) {
    F_LOCK();
    for (int i = 0; i < MAX_SETS; i++) {
        policy_free(s_sets[i].pol);
        memset(&s_sets[i], 0, sizeof(s_sets[i]));
    }
    memset(s_flows, 0, sizeof(s_flows));
    memset(&s_stats, 0, sizeof(s_stats));
    s_configured = false;
    s_self_ip = 0;
    s_nlocal_routes = 0;
    F_UNLOCK();
}

void ml_filter_set_local(uint32_t self_ip, const ml_route_t *routes, int n) {
    if (n < 0 || !routes) n = 0;
    if (n > ML_MAX_ROUTES) n = ML_MAX_ROUTES;
    F_LOCK();
    s_self_ip = self_ip;
    if (n) memcpy(s_local_routes, routes, (size_t)n * sizeof(ml_route_t));
    s_nlocal_routes = n;
    F_UNLOCK();
}

bool ml_filter_update_from_map(const cJSON *map) {
    if (!map || s_mode == ML_FILTER_MODE_OFF) return false;
    const cJSON *single = cJSON_GetObjectItemCaseSensitive(map, "PacketFilter");
    const cJSON *multi = cJSON_GetObjectItemCaseSensitive(map, "PacketFilters");
    bool changed = false;

    if (cJSON_IsObject(multi)) {
        const cJSON *e;
        cJSON_ArrayForEach(e, multi) {
            if (!e->string) continue;
            if (cJSON_IsNull(e)) {
                F_LOCK(); set_replace_locked(e->string, NULL); F_UNLOCK();
                changed = true;
                continue;
            }
            policy_t *pol = policy_parse(e);
            if (!pol) { F_LOGW("PacketFilters[%s] rejected (invalid or too large); keeping previous", e->string); continue; }
            F_LOCK(); set_replace_locked(e->string, pol); s_configured = true; F_UNLOCK();
            changed = true;
        }
    } else if (cJSON_IsArray(single) || cJSON_IsNull(single)) {
        /* JSON null is treated like absent (unchanged). */
        if (cJSON_IsArray(single)) {
            policy_t *pol = policy_parse(single);
            if (!pol) {
                F_LOGW("PacketFilter rejected (invalid or too large); keeping previous");
            } else {
                F_LOCK(); set_replace_locked("base", pol); s_configured = true; F_UNLOCK();
                changed = true;
            }
        }
    }
    if (changed) {
        F_LOCK(); s_stats.rules = count_rules_locked(); s_stats.configured = s_configured; F_UNLOCK();
        F_LOGI("Packet filter updated: %u rule(s)%s", (unsigned)s_stats.rules,
               s_mode == ML_FILTER_MODE_LOG ? " (log-only mode)" : "");
    }
    return changed;
}

static bool proto_allowed(const rule_t *r, uint8_t proto) {
    if (r->nprotos == 0) {
        return proto == PROTO_TCP || proto == PROTO_UDP || proto == PROTO_ICMP;
    }
    for (int i = 0; i < r->nprotos; i++) if (r->protos[i] == proto) return true;
    return false;
}

static bool policy_allows_locked(uint32_t src, uint32_t dst, uint8_t proto, bool has_port, uint16_t dport) {
    for (int si = 0; si < MAX_SETS; si++) {
        const policy_t *p = s_sets[si].pol;
        if (!p) continue;
        for (uint32_t ri = 0; ri < p->nrules; ri++) {
            const rule_t *r = &p->rules[ri];
            if (!proto_allowed(r, proto)) continue;
            bool src_ok = false;
            for (uint32_t k = 0; k < r->src_count && !src_ok; k++) {
                const range_t *sr = &p->src[r->src_first + k];
                src_ok = src >= sr->lo && src <= sr->hi;
            }
            if (!src_ok) continue;
            for (uint32_t k = 0; k < r->dst_count; k++) {
                const dst_t *d = &p->dst[r->dst_first + k];
                if (dst < d->ip.lo || dst > d->ip.hi) continue;
                if (!has_port || (dport >= d->port_lo && dport <= d->port_hi)) return true;
            }
        }
    }
    return false;
}

static bool flow_match_locked(uint32_t peer, uint16_t peer_port, uint32_t local,
                              uint16_t local_port, uint32_t now) {
    for (int i = 0; i < FLOW_SLOTS; i++) {
        flow_t *f = &s_flows[i];
        if (f->used && f->peer_ip == peer && f->peer_port == peer_port &&
            f->local_ip == local && f->local_port == local_port &&
            (uint32_t)(now - f->ts) < FLOW_TIMEOUT_MS) {
            return true;
        }
    }
    return false;
}

static inline uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

void ml_filter_note_outbound(const uint8_t *pkt, size_t len, uint32_t now) {
    if (s_mode == ML_FILTER_MODE_OFF || !pkt || len < 20 || (pkt[0] >> 4) != 4) return;
    size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (pkt[9] != PROTO_UDP || ihl < 20 || len < ihl + 4) return;
    if (rd16(pkt + 6) & 0x1FFF) return;                /* non-first fragment */
    uint32_t local = rd32(pkt + 12), peer = rd32(pkt + 16);
    uint16_t local_port = rd16(pkt + ihl), peer_port = rd16(pkt + ihl + 2);
    F_LOCK();
    flow_t *slot = NULL, *oldest = &s_flows[0];
    for (int i = 0; i < FLOW_SLOTS; i++) {
        flow_t *f = &s_flows[i];
        if (f->used && f->peer_ip == peer && f->peer_port == peer_port &&
            f->local_ip == local && f->local_port == local_port) { slot = f; break; }
        if (!f->used && !slot) slot = f;
        if (f->used && (uint32_t)(now - f->ts) > (uint32_t)(now - oldest->ts)) oldest = f;
    }
    if (!slot) slot = oldest;
    slot->used = true;
    slot->peer_ip = peer;
    slot->local_ip = local;
    slot->peer_port = peer_port;
    slot->local_port = local_port;
    slot->ts = now;
    F_UNLOCK();
}

/* Destination check, done in every mode: see ml_filter.h. */
static bool dst_is_local(uint32_t dst) {
    F_LOCK();
    bool ok = s_self_ip == 0 || dst == s_self_ip ||
              ml_routes_contain(s_local_routes, s_nlocal_routes, dst);
    if (!ok) s_stats.dropped++;
    F_UNLOCK();
    return ok;
}

bool ml_filter_check_inbound(const uint8_t *pkt, size_t len, uint32_t now) {
    if (!pkt || len < 20 || (pkt[0] >> 4) != 4) return true;   /* non-IPv4 is handled by cryptokey routing */
    size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > len) return false;
    uint8_t proto = pkt[9];
    uint32_t src = rd32(pkt + 12), dst = rd32(pkt + 16);
    if (!dst_is_local(dst)) {
        F_LOGD("drop proto=%u to %u.%u.%u.%u: destination not local", proto,
               (unsigned)(dst >> 24), (unsigned)((dst >> 16) & 0xFF),
               (unsigned)((dst >> 8) & 0xFF), (unsigned)(dst & 0xFF));
        return false;
    }
    if (s_mode == ML_FILTER_MODE_OFF) return true;
    bool first_frag = (rd16(pkt + 6) & 0x1FFF) == 0;
    bool has_port = false;
    uint16_t dport = 0;
    bool accept = false;
    const char *why = "no rule";

    if (!first_frag) {
        accept = true; why = "fragment";
    } else if (proto == PROTO_ICMP) {
        if (len < ihl + 1) return false;
        uint8_t type = pkt[ihl];
        if (type == 0 || type == 3 || type == 11 || type == 12) { accept = true; why = "icmp reply/error"; }
    } else if (proto == PROTO_TCP) {
        if (len < ihl + 14) return false;
        uint8_t flags = pkt[ihl + 13];
        dport = rd16(pkt + ihl + 2);
        has_port = true;
        if (!((flags & 0x02) && !(flags & 0x10))) { accept = true; why = "tcp non-syn"; }
    } else if (proto == PROTO_UDP || proto == PROTO_SCTP) {
        if (len < ihl + 4) return false;
        dport = rd16(pkt + ihl + 2);
        has_port = true;
    }

    F_LOCK();
    if (!accept && proto == PROTO_UDP && flow_match_locked(src, rd16(pkt + ihl), dst, dport, now)) {
        accept = true; why = "udp reply";
    }
    if (!accept && !s_configured) { accept = true; why = "no policy yet"; }
    if (!accept && policy_allows_locked(src, dst, proto, has_port, dport)) { accept = true; why = "rule"; }
    if (accept) s_stats.accepted++; else s_stats.dropped++;
    F_UNLOCK();

    (void)why;   /* only used by the debug log */
    if (!accept) {
        F_LOGD("drop proto=%u %u.%u.%u.%u -> port %u (%s)%s", proto,
               (unsigned)(src >> 24), (unsigned)((src >> 16) & 0xFF), (unsigned)((src >> 8) & 0xFF),
               (unsigned)(src & 0xFF), dport, why, s_mode == ML_FILTER_MODE_LOG ? " [log-only]" : "");
        return s_mode != ML_FILTER_MODE_ENFORCE;
    }
    return true;
}

void ml_filter_get_stats(ml_filter_stats_t *out) {
    if (!out) return;
    F_LOCK();
    *out = s_stats;
    F_UNLOCK();
}
