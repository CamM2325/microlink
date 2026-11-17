/*
 * ml_routes: parse and format advertised subnet routes. See ml_routes.h.
 */
#include "ml_routes.h"
#include <stdio.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "lwip/ip6_addr.h"
#else
#include <arpa/inet.h>
#endif

static uint32_t prefix_mask(uint8_t len) {
    return len == 0 ? 0 : 0xFFFFFFFFu << (32 - len);
}

static bool is_sep(char c) {
    return c == ',' || c == ' ' || c == ';' || c == '\n' || c == '\r' || c == '\t';
}

/* Parse "a.b.c.d" or "a.b.c.d/len" in [s, end). */
static bool parse_cidr(const char *s, const char *end, ml_route_t *out) {
    uint32_t addr = 0;
    for (int part = 0; part < 4; part++) {
        if (part > 0) {
            if (s >= end || *s != '.') return false;
            s++;
        }
        uint32_t oct = 0;
        int digits = 0;
        while (s < end && *s >= '0' && *s <= '9' && digits < 3) {
            oct = oct * 10 + (uint32_t)(*s - '0');
            s++;
            digits++;
        }
        if (digits == 0 || oct > 255) return false;
        addr = (addr << 8) | oct;
    }
    uint32_t len = 32;
    if (s < end) {
        if (*s != '/') return false;
        s++;
        len = 0;
        int digits = 0;
        while (s < end && *s >= '0' && *s <= '9' && digits < 2) {
            len = len * 10 + (uint32_t)(*s - '0');
            s++;
            digits++;
        }
        if (digits == 0 || len > 32) return false;
    }
    if (s != end) return false;
    out->len = (uint8_t)len;
    out->net = addr & prefix_mask(out->len);
    return true;
}

int ml_routes_parse(const char *list, ml_route_t *out, int max) {
    int n = 0;
    if (!list) return 0;
    const char *p = list;
    while (*p) {
        while (*p && is_sep(*p)) p++;
        if (!*p) break;
        const char *start = p;
        while (*p && !is_sep(*p)) p++;
        size_t tok_len = (size_t)(p - start);

        if (tok_len == 4 && memcmp(start, "::/0", 4) == 0) continue;
        if (memchr(start, ':', tok_len)) continue;   /* IPv6: ml_routes_parse6() */

        ml_route_t r;
        if (!parse_cidr(start, p, &r)) return -1;
        bool dup = false;
        for (int i = 0; i < n; i++) {
            if (out[i].net == r.net && out[i].len == r.len) dup = true;
        }
        if (dup) continue;
        if (n >= max) return -1;
        out[n++] = r;
    }
    return n;
}

/* IPv6 "addr" or "addr/len" in [s, end). */
static bool parse_cidr6(const char *s, const char *end, ml_route6_t *out) {
    const char *slash = memchr(s, '/', (size_t)(end - s));
    const char *aend = slash ? slash : end;
    char buf[48];
    size_t n = (size_t)(aend - s);
    if (n == 0 || n >= sizeof(buf)) return false;
    memcpy(buf, s, n);
    buf[n] = '\0';
#ifdef ESP_PLATFORM
    ip6_addr_t a;
    if (!ip6addr_aton(buf, &a)) return false;
    memcpy(out->net, a.addr, 16);
#else
    if (inet_pton(AF_INET6, buf, out->net) != 1) return false;
#endif
    unsigned len = 128;
    if (slash) {
        const char *p = slash + 1;
        if (p >= end || end - p > 3) return false;
        len = 0;
        for (; p < end; p++) {
            if (*p < '0' || *p > '9') return false;
            len = len * 10 + (unsigned)(*p - '0');
        }
        if (len > 128) return false;
    }
    out->len = (uint8_t)len;
    for (int i = 0; i < 16; i++) {          /* clear host bits */
        int keep = (int)len - i * 8;
        out->net[i] &= keep >= 8 ? 0xFF : keep <= 0 ? 0 : (uint8_t)(0xFF << (8 - keep));
    }
    return true;
}

int ml_routes_parse6(const char *list, ml_route6_t *out, int max) {
    int n = 0;
    if (!list) return 0;
    const char *p = list;
    while (*p) {
        while (*p && is_sep(*p)) p++;
        if (!*p) break;
        const char *start = p;
        while (*p && !is_sep(*p)) p++;
        size_t tok_len = (size_t)(p - start);
        if (!memchr(start, ':', tok_len)) continue;              /* IPv4: ml_routes_parse() */
        if (tok_len == 4 && memcmp(start, "::/0", 4) == 0) continue;   /* with 0.0.0.0/0 */

        ml_route6_t r;
        if (!parse_cidr6(start, p, &r) || r.len == 0) return -1;
        bool dup = false;
        for (int i = 0; i < n; i++) {
            if (out[i].len == r.len && memcmp(out[i].net, r.net, 16) == 0) dup = true;
        }
        if (dup) continue;
        if (n >= max) return -1;
        out[n++] = r;
    }
    return n;
}

bool ml_routes6_contain(const ml_route6_t *routes, int n, const uint8_t ip[16]) {
    for (int i = 0; i < n; i++) {
        int bits = routes[i].len;
        bool match = true;
        for (int b = 0; b < 16 && bits > 0 && match; b++, bits -= 8) {
            uint8_t m = bits >= 8 ? 0xFF : (uint8_t)(0xFF << (8 - bits));
            match = (ip[b] & m) == routes[i].net[b];
        }
        if (match) return true;
    }
    return false;
}

/* RFC 5952 text form: lowercase, longest run of zero groups as "::". */
void ml_routes6_format(const ml_route6_t *r, char *buf, size_t size) {
    uint16_t g[8];
    for (int i = 0; i < 8; i++) g[i] = (uint16_t)(r->net[2 * i] << 8 | r->net[2 * i + 1]);
    int best = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (g[i]) { i++; continue; }
        int j = i;
        while (j < 8 && !g[j]) j++;
        if (j - i > best_len && j - i >= 2) { best = i; best_len = j - i; }
        i = j;
    }
    char tmp[48];
    size_t o = 0;
    for (int i = 0; i < 8; i++) {
        if (i == best) {
            o += (size_t)snprintf(tmp + o, sizeof(tmp) - o, "::");
            i += best_len - 1;
            continue;
        }
        if (o && tmp[o - 1] != ':') tmp[o++] = ':';
        o += (size_t)snprintf(tmp + o, sizeof(tmp) - o, "%x", g[i]);
    }
    tmp[o] = '\0';
    snprintf(buf, size, "%s/%u", tmp, (unsigned)r->len);
}

bool ml_routes_is_exit_node(const ml_route_t *routes, int n) {
    for (int i = 0; i < n; i++) {
        if (routes[i].len == 0) return true;
    }
    return false;
}

bool ml_routes_contain(const ml_route_t *routes, int n, uint32_t ip) {
    for (int i = 0; i < n; i++) {
        if ((ip & prefix_mask(routes[i].len)) == routes[i].net) return true;
    }
    return false;
}

void ml_routes_format(const ml_route_t *r, char *buf, size_t size) {
    snprintf(buf, size, "%u.%u.%u.%u/%u",
             (unsigned)(r->net >> 24), (unsigned)((r->net >> 16) & 0xFF),
             (unsigned)((r->net >> 8) & 0xFF), (unsigned)(r->net & 0xFF),
             (unsigned)r->len);
}
