/*
 * ml_routes: parse and format advertised subnet routes. See ml_routes.h.
 */
#include "ml_routes.h"
#include <stdio.h>
#include <string.h>

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
