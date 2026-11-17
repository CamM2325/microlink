/* Host tests for ml_nat66 (exit-node IPv6 masquerading). */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "ml_nat66.h"

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static void a6(const char *s, uint8_t out[16]) { inet_pton(AF_INET6, s, out); }

/* Full transport checksum over the IPv6 pseudo-header and payload. */
static uint16_t csum6(const uint8_t *pkt, size_t len) {
    uint32_t sum = 0;
    for (int i = 8; i < 40; i += 2) sum += (uint32_t)(pkt[i] << 8 | pkt[i + 1]);
    uint32_t plen = (uint32_t)(len - 40);
    sum += plen >> 16; sum += plen & 0xFFFF;
    sum += pkt[6];
    for (size_t i = 40; i < len; i += 2) sum += (uint32_t)(pkt[i] << 8 | (i + 1 < len ? pkt[i + 1] : 0));
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static size_t csum_off(uint8_t proto) { return proto == 6 ? 56 : proto == 17 ? 46 : 42; }

/* proto 6/17/58; for 58 sport is the echo identifier and type is 128/129. */
static size_t build(uint8_t *b, uint8_t proto, const char *src, const char *dst,
                    uint16_t sport, uint16_t dport, uint8_t icmp_type) {
    size_t tl = proto == 6 ? 20 : 8;
    size_t len = 40 + tl + 12;              /* 12 bytes of payload */
    memset(b, 0, len);
    b[0] = 0x60; b[4] = (uint8_t)((len - 40) >> 8); b[5] = (uint8_t)(len - 40); b[6] = proto; b[7] = 64;
    a6(src, b + 8); a6(dst, b + 24);
    if (proto == 58) {
        b[40] = icmp_type; b[44] = (uint8_t)(sport >> 8); b[45] = (uint8_t)sport; b[47] = 1;
    } else {
        b[40] = (uint8_t)(sport >> 8); b[41] = (uint8_t)sport; b[42] = (uint8_t)(dport >> 8); b[43] = (uint8_t)dport;
        if (proto == 6) { b[52] = 0x50; b[53] = 0x02; } else { b[44] = (uint8_t)((len - 40) >> 8); b[45] = (uint8_t)(len - 40); }
    }
    for (size_t i = 40 + tl; i < len; i++) b[i] = (uint8_t)(i * 7);
    uint16_t c = csum6(b, len);
    b[csum_off(proto)] = (uint8_t)(c >> 8); b[csum_off(proto) + 1] = (uint8_t)c;
    return len;
}

static int valid(const uint8_t *b, size_t len) { return csum6(b, len) == 0; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

#define CLIENT "fd7a:115c:a1e0::5"
#define LAN    "2601:483:4001:fc7b::99"
#define SERVER "2606:4700:4700::1111"

static void round_trip(uint8_t proto) {
    uint8_t b[128], lan[16], client[16];
    a6(LAN, lan); a6(CLIENT, client);
    size_t n = build(b, proto, CLIENT, SERVER, 5555, 443, 128);
    CHECK(valid(b, n));
    CHECK(ml_nat66_out(b, n, lan, 1000) == 0);
    CHECK(memcmp(b + 8, lan, 16) == 0);                 /* source is now ours */
    CHECK(valid(b, n));                                 /* checksum still right */
    uint16_t mport = rd16(b + (proto == 58 ? 44 : 40));
    CHECK(mport >= ML_NAT66_PORT_LO && mport <= ML_NAT66_PORT_HI);

    /* the reply */
    uint8_t r[128];
    size_t rn = build(r, proto, SERVER, LAN, 443, mport, 129);
    if (proto == 58) { r[44] = (uint8_t)(mport >> 8); r[45] = (uint8_t)mport; }
    r[csum_off(proto)] = 0; r[csum_off(proto) + 1] = 0;   /* recompute after the id change */
    uint16_t c = csum6(r, rn); r[csum_off(proto)] = (uint8_t)(c >> 8); r[csum_off(proto) + 1] = (uint8_t)c;
    CHECK(ml_nat66_in(r, rn, 1500) == 1);
    CHECK(memcmp(r + 24, client, 16) == 0);             /* back to the peer */
    CHECK(rd16(r + (proto == 58 ? 44 : 42)) == 5555);
    CHECK(valid(r, rn));
}

int main(void) {
    uint8_t b[128], lan[16];
    a6(LAN, lan);

    ml_nat66_reset();
    round_trip(6);
    round_trip(17);
    round_trip(58);

    /* Same flow, same mapping; a port inside our range is kept. */
    ml_nat66_reset();
    size_t n = build(b, 17, CLIENT, SERVER, 40000, 53, 0);
    CHECK(ml_nat66_out(b, n, lan, 0) == 0 && rd16(b + 40) == 40000);
    n = build(b, 17, CLIENT, SERVER, 40000, 53, 0);
    CHECK(ml_nat66_out(b, n, lan, 10) == 0 && rd16(b + 40) == 40000);
    CHECK(ml_nat66_count(10) == 1);
    /* another peer with the same port gets a different mapped port */
    n = build(b, 17, "fd7a:115c:a1e0::6", SERVER, 40000, 53, 0);
    CHECK(ml_nat66_out(b, n, lan, 20) == 0 && rd16(b + 40) != 40000);

    /* Unknown traffic to us is left alone. */
    n = build(b, 17, SERVER, LAN, 53, 41000, 0);
    CHECK(ml_nat66_in(b, n, 30) == 0);
    n = build(b, 17, SERVER, LAN, 53, 9000, 0);          /* outside the mapped range */
    CHECK(ml_nat66_in(b, n, 30) == 0);

    /* Not translatable outbound: ICMPv6 other than echo request, short or
     * UDP without checksum. */
    n = build(b, 58, CLIENT, SERVER, 1, 0, 1);
    CHECK(ml_nat66_out(b, n, lan, 40) == -1);
    n = build(b, 6, CLIENT, SERVER, 1, 80, 0);
    CHECK(ml_nat66_out(b, 50, lan, 40) == -1);
    n = build(b, 17, CLIENT, SERVER, 1, 80, 0);
    b[46] = b[47] = 0;
    CHECK(ml_nat66_out(b, n, lan, 40) == -1);

    /* Mappings expire (UDP: 120 s). */
    ml_nat66_reset();
    n = build(b, 17, CLIENT, SERVER, 1234, 53, 0);
    CHECK(ml_nat66_out(b, n, lan, 0) == 0);
    CHECK(ml_nat66_count(1000) == 1 && ml_nat66_count(200000) == 0);

    /* A full table reuses the least recently used mapping. */
    ml_nat66_reset();
    for (int i = 0; i < ML_NAT66_SLOTS + 10; i++) {
        n = build(b, 6, CLIENT, SERVER, (uint16_t)(1000 + i), 80, 0);
        CHECK(ml_nat66_out(b, n, lan, (uint32_t)i) == 0);
    }
    CHECK(ml_nat66_count(1000) == ML_NAT66_SLOTS);

    /* Source scope: a global destination needs a global source. */
    {
        uint8_t g[16], ula[16], ll[16], dg[16], du[16];
        a6("2601:483:4001:fc7b::99", g); a6("fd12::99", ula); a6("fe80::99", ll);
        a6(SERVER, dg); a6("fd12::1", du);
        CHECK(ml_nat66_source_ok(g, dg));
        CHECK(!ml_nat66_source_ok(ula, dg));
        CHECK(!ml_nat66_source_ok(ll, dg));
        CHECK(ml_nat66_source_ok(ula, du));
        CHECK(ml_nat66_source_ok(g, du));
        CHECK(!ml_nat66_source_ok(ll, du));
    }

    /* ICMPv6 "no route" back to the peer. */
    {
        uint8_t self6[16], out[1280], client[16];
        a6("fd7a:115c:a1e0::1", self6); a6(CLIENT, client);
        n = build(b, 6, CLIENT, SERVER, 5555, 443, 0);
        size_t m = ml_nat66_unreachable(b, n, self6, out, sizeof(out));
        CHECK(m == 48 + n);
        CHECK(out[6] == 58 && out[40] == 1 && out[41] == 0);
        CHECK(memcmp(out + 8, self6, 16) == 0 && memcmp(out + 24, client, 16) == 0);
        CHECK(memcmp(out + 48, b, n) == 0);
        CHECK(csum6(out, m) == 0);
        n = build(b, 58, CLIENT, SERVER, 1, 0, 128);              /* echo request: answered */
        CHECK(ml_nat66_unreachable(b, n, self6, out, sizeof(out)) > 0);
        n = build(b, 58, CLIENT, SERVER, 1, 0, 1);                /* an error: never answered */
        CHECK(ml_nat66_unreachable(b, n, self6, out, sizeof(out)) == 0);
        CHECK(ml_nat66_unreachable(b, 30, self6, out, sizeof(out)) == 0);
        static uint8_t big[1500];                                  /* quoted part is capped */
        memcpy(big, b, n);
        big[4] = (uint8_t)((1500 - 40) >> 8); big[5] = (uint8_t)(1500 - 40); big[6] = 17;
        CHECK(ml_nat66_unreachable(big, sizeof(big), self6, out, sizeof(out)) == 1280);
    }

    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("all NAT66 tests passed\n");
    return 0;
}
