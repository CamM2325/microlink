/* Host tests for ml_filter (tailnet packet filter / ACL enforcement). */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "ml_filter.h"
#include <arpa/inet.h>

static int failures = 0;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

#define ME   "100.64.0.1"
static uint32_t ip(const char *s) { unsigned a, b, c, d; sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d); return (a << 24) | (b << 16) | (c << 8) | d; }

/* Build a minimal IPv4 packet. proto 1/6/17; flags for TCP; icmp_type for ICMP. */
static size_t pkt(uint8_t *b, uint8_t proto, const char *src, const char *dst,
                  uint16_t sport, uint16_t dport, uint8_t tcp_flags, uint8_t icmp_type) {
    memset(b, 0, 64);
    b[0] = 0x45; b[9] = proto;
    uint32_t s = ip(src), d = ip(dst);
    for (int i = 0; i < 4; i++) { b[12 + i] = (uint8_t)(s >> (24 - 8 * i)); b[16 + i] = (uint8_t)(d >> (24 - 8 * i)); }
    size_t n = 28;
    if (proto == 1) {
        b[20] = icmp_type;
    } else {
        b[20] = (uint8_t)(sport >> 8); b[21] = (uint8_t)sport; b[22] = (uint8_t)(dport >> 8); b[23] = (uint8_t)dport;
        if (proto == 6) { b[33] = tcp_flags; n = 40; }
    }
    b[2] = (uint8_t)(n >> 8); b[3] = (uint8_t)n;   /* IP total length */
    return n;
}

/* Minimal IPv6 packet: proto 6/17/58, TCP flags, ICMPv6 type. */
static size_t pkt6(uint8_t *b, uint8_t proto, const char *src, const char *dst,
                   uint16_t sport, uint16_t dport, uint8_t tcp_flags, uint8_t icmp_type) {
    memset(b, 0, 96);
    size_t tl = proto == 6 ? 20 : 8;
    b[0] = 0x60; b[5] = (uint8_t)tl; b[6] = proto; b[7] = 64;
    inet_pton(AF_INET6, src, b + 8);
    inet_pton(AF_INET6, dst, b + 24);
    if (proto == 58) { b[40] = icmp_type; }
    else { b[40] = (uint8_t)(sport >> 8); b[41] = (uint8_t)sport; b[42] = (uint8_t)(dport >> 8); b[43] = (uint8_t)dport; }
    if (proto == 6) b[53] = tcp_flags;
    return 40 + tl;
}
#define ME6 "fd7a:115c:a1e0::1"
static bool in6(uint8_t proto, const char *src, const char *dst, uint16_t dport, uint8_t flags, uint8_t icmp) {
    uint8_t b[96];
    size_t n = pkt6(b, proto, src, dst, 1234, dport, flags, icmp);
    return ml_filter_check_inbound(b, n, 1000);
}

static void apply(const char *json) {
    cJSON *m = cJSON_Parse(json);
    if (!m) { fprintf(stderr, "bad test json: %s\n", json); failures++; return; }
    ml_filter_update_from_map(m);
    cJSON_Delete(m);
}

static bool in(uint8_t proto, const char *src, uint16_t sport, uint16_t dport, uint8_t flags, uint8_t icmp) {
    uint8_t b[64];
    size_t n = pkt(b, proto, src, ME, sport, dport, flags, icmp);
    return ml_filter_check_inbound(b, n, 1000);
}

#define SYN 0x02
#define ACK 0x10

int main(void) {
    ml_filter_init(ML_FILTER_MODE_ENFORCE);

    /* Before any policy: nothing new gets in (as in Tailscale); replies and
     * errors do. */
    CHECK(!in(17, "100.64.0.9", 1234, 22, 0, 0));
    CHECK(!in(6, "100.64.0.9", 1234, 22, SYN, 0));
    CHECK(in(1, "100.64.0.9", 0, 0, 0, 0));

    /* Tailscale's default allow-all policy. */
    apply("{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]}");
    CHECK(in(17, "100.64.0.9", 1234, 22, 0, 0));
    CHECK(in(6, "100.64.0.9", 1234, 22, SYN, 0));

    /* Restrictive: only 100.64.0.5 may reach UDP/TCP 9000 (and ICMP). */
    apply("{\"PacketFilter\":[{\"SrcIPs\":[\"100.64.0.5\",\"fd7a:115c:a1e0::5\"],"
          "\"DstPorts\":[{\"IP\":\"" ME "\",\"Ports\":{\"First\":9000,\"Last\":9000}}]}]}");
    CHECK(in(17, "100.64.0.5", 1234, 9000, 0, 0));
    CHECK(!in(17, "100.64.0.6", 1234, 9000, 0, 0));      /* other source */
    CHECK(!in(17, "100.64.0.5", 1234, 22, 0, 0));        /* other port */
    CHECK(!in(6, "100.64.0.5", 1234, 22, SYN, 0));       /* new TCP connection */
    CHECK(in(6, "100.64.0.5", 1234, 22, ACK, 0));        /* non-SYN TCP */
    CHECK(in(6, "100.64.0.6", 1234, 22, SYN | ACK, 0));  /* SYN-ACK = reply */
    CHECK(in(1, "100.64.0.5", 0, 0, 0, 8));              /* ICMP echo from allowed src */
    CHECK(!in(1, "100.64.0.6", 0, 0, 0, 8));             /* echo request from other src */
    CHECK(in(1, "100.64.0.6", 0, 0, 0, 0));              /* echo reply always */

    /* UDP replies to flows the device started. */
    {
        uint8_t b[64];
        size_t n = pkt(b, 17, ME, "100.64.0.7", 5000, 7000, 0, 0);
        ml_filter_note_outbound(b, n, 1000);
        CHECK(in(17, "100.64.0.7", 7000, 5000, 0, 0));
        CHECK(!in(17, "100.64.0.7", 7001, 5000, 0, 0));
        CHECK(!in(17, "100.64.0.8", 7000, 5000, 0, 0));
        n = pkt(b, 17, "100.64.0.7", ME, 7000, 5000, 0, 0);
        CHECK(!ml_filter_check_inbound(b, n, 1000 + 130000));  /* flow expired */
    }

    /* IPProto restricts protocols. */
    apply("{\"PacketFilter\":[{\"SrcIPs\":[\"100.64.0.0/24\"],\"IPProto\":[6],"
          "\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":80,\"Last\":90}}]}]}");
    CHECK(in(6, "100.64.0.200", 1, 85, SYN, 0));
    CHECK(!in(17, "100.64.0.200", 1, 85, 0, 0));
    CHECK(!in(6, "100.64.1.1", 1, 85, SYN, 0));          /* outside /24 */

    /* Ranges, absent field = unchanged, null = unchanged. */
    apply("{\"PacketFilter\":[{\"SrcIPs\":[\"100.64.0.10-100.64.0.20\"],"
          "\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":1,\"Last\":65535}}]}]}");
    CHECK(in(17, "100.64.0.15", 1, 53, 0, 0));
    CHECK(!in(17, "100.64.0.21", 1, 53, 0, 0));
    apply("{\"Peers\":[]}");
    CHECK(in(17, "100.64.0.15", 1, 53, 0, 0));
    apply("{\"PacketFilter\":null}");
    CHECK(in(17, "100.64.0.15", 1, 53, 0, 0));
    apply("{\"PacketFilter\":\"garbage\"}");
    CHECK(in(17, "100.64.0.15", 1, 53, 0, 0));

    /* Empty filter = deny all new inbound (except replies/errors). */
    apply("{\"PacketFilter\":[]}");
    CHECK(!in(17, "100.64.0.15", 1, 53, 0, 0));
    CHECK(in(1, "100.64.0.15", 0, 0, 0, 3));

    /* CapGrant-only rules grant nothing. */
    apply("{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"CapGrant\":[{\"Dsts\":[\"*\"],\"Caps\":[\"x\"]}]}]}");
    CHECK(!in(17, "100.64.0.15", 1, 53, 0, 0));

    /* PacketFilters map: named sets add up; null deletes a set. */
    apply("{\"PacketFilters\":{\"base\":[{\"SrcIPs\":[\"100.64.0.5\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}],"
          "\"extra\":[{\"SrcIPs\":[\"100.64.0.6\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]}}");
    CHECK(in(17, "100.64.0.5", 1, 53, 0, 0));
    CHECK(in(17, "100.64.0.6", 1, 53, 0, 0));
    apply("{\"PacketFilters\":{\"extra\":null}}");
    CHECK(in(17, "100.64.0.5", 1, 53, 0, 0));
    CHECK(!in(17, "100.64.0.6", 1, 53, 0, 0));

    /* Malformed packets. */
    {
        uint8_t b[64];
        size_t n = pkt(b, 6, "100.64.0.5", ME, 1, 22, SYN, 0);
        CHECK(!ml_filter_check_inbound(b, 25, 1000));     /* truncated TCP header */
        b[0] = 0x4F;                                      /* IHL 60 > len */
        CHECK(!ml_filter_check_inbound(b, n, 1000));
    }

    /* Log-only mode accepts but counts. */
    ml_filter_stats_t st0, st1;
    ml_filter_get_stats(&st0);
    ml_filter_init(ML_FILTER_MODE_LOG);
    CHECK(in(17, "100.64.0.6", 1, 53, 0, 0));
    ml_filter_get_stats(&st1);
    CHECK(st1.dropped == st0.dropped + 1);

    /* Reset clears the policy: back to allowing nothing new. */
    ml_filter_reset();
    ml_filter_init(ML_FILTER_MODE_ENFORCE);
    CHECK(!in(17, "100.64.0.6", 1, 53, 0, 0));

#define ALLOW_ALL "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]"
    /* PacketFilters "*" clears every earlier set, including base. */
    apply("{\"PacketFilter\":" ALLOW_ALL "}");
    apply("{\"PacketFilters\":{\"a-set-name-that-is-longer-than-twenty-four-chars\":" ALLOW_ALL "}}");
    CHECK(in(6, "100.64.0.6", 1, 22, SYN, 0));
    apply("{\"PacketFilters\":{\"*\":null,\"web\":[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":80,\"Last\":80}}]}]}}");
    CHECK(!in(6, "100.64.0.6", 1, 22, SYN, 0));        /* allow-all sets gone */
    CHECK(in(6, "100.64.0.6", 1, 80, SYN, 0));

    /* A long set name can be deleted again. */
    apply("{\"PacketFilters\":{\"a-set-name-that-is-longer-than-twenty-four-chars\":" ALLOW_ALL "}}");
    CHECK(in(6, "100.64.0.6", 1, 22, SYN, 0));
    apply("{\"PacketFilters\":{\"a-set-name-that-is-longer-than-twenty-four-chars\":null}}");
    CHECK(!in(6, "100.64.0.6", 1, 22, SYN, 0));

    /* A policy too large to apply allows nothing (not the previous rules). */
    {
        apply("{\"PacketFilter\":" ALLOW_ALL "}");
        CHECK(in(6, "100.64.0.6", 1, 22, SYN, 0));
        static char big[5000 * 20 + 256];
        size_t o = (size_t)sprintf(big, "{\"PacketFilter\":[{\"SrcIPs\":[");
        for (int i = 0; i < 5000; i++) o += (size_t)sprintf(big + o, "%s\"10.%d.%d.1\"", i ? "," : "", i / 250, i % 250);
        sprintf(big + o, "],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":81,\"Last\":81}}]}]}");
        apply(big);
        CHECK(!in(6, "100.64.0.6", 1, 22, SYN, 0));
        CHECK(!in(6, "10.0.0.1", 1, 81, SYN, 0));
        apply("{\"PacketFilter\":" ALLOW_ALL "}");
    }

    /* Header fields come from within the IP length, not tunnel padding,
     * and short first fragments are dropped. */
    {
        uint8_t b[128];
        apply("{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":80,\"Last\":80}}]}]}");
        size_t n = pkt(b, 6, "100.64.0.6", ME, 1, 22, SYN, 0);
        b[2] = 0; b[3] = 28;                              /* IP length ends inside the TCP header */
        b[33] = 0x10;                                     /* "ACK" only in the padding */
        CHECK(!ml_filter_check_inbound(b, n, 1000));
        n = pkt(b, 6, "100.64.0.6", ME, 1, 22, ACK, 0);
        b[6] = 0x20;                                      /* MF, offset 0: 40-byte first fragment */
        CHECK(!ml_filter_check_inbound(b, n, 1000));
        apply("{\"PacketFilter\":" ALLOW_ALL "}");
    }

    /* Advertised routes: parsing. */
    {
        ml_route_t r[ML_MAX_ROUTES];
        char s[20];
        CHECK(ml_routes_parse(NULL, r, ML_MAX_ROUTES) == 0);
        CHECK(ml_routes_parse(" ,\n", r, ML_MAX_ROUTES) == 0);
        CHECK(ml_routes_parse("192.168.1.5/24, 10.0.0.0/8;10.0.0.0/8\n172.16.0.1", r, ML_MAX_ROUTES) == 3);
        CHECK(r[0].net == ip("192.168.1.0") && r[0].len == 24);   /* host bits cleared */
        CHECK(r[1].net == ip("10.0.0.0") && r[1].len == 8);       /* duplicate dropped */
        CHECK(r[2].net == ip("172.16.0.1") && r[2].len == 32);    /* bare address */
        ml_routes_format(&r[0], s, sizeof(s));
        CHECK(strcmp(s, "192.168.1.0/24") == 0);
        CHECK(!ml_routes_is_exit_node(r, 3));
        CHECK(ml_routes_contain(r, 3, ip("10.200.0.1")));
        CHECK(!ml_routes_contain(r, 3, ip("172.16.0.2")));
        CHECK(ml_routes_parse("0.0.0.0/0 ::/0", r, ML_MAX_ROUTES) == 1);
        CHECK(ml_routes_is_exit_node(r, 1));
        CHECK(ml_routes_contain(r, 1, ip("8.8.8.8")));
        ml_routes_format(&r[0], s, sizeof(s));
        CHECK(strcmp(s, "0.0.0.0/0") == 0);
        CHECK(ml_routes_parse("192.168.1.0/33", r, ML_MAX_ROUTES) == -1);
        CHECK(ml_routes_parse("256.1.1.1/8", r, ML_MAX_ROUTES) == -1);
        CHECK(ml_routes_parse("1.2.3/24", r, ML_MAX_ROUTES) == -1);
        CHECK(ml_routes_parse("1.2.3.4/", r, ML_MAX_ROUTES) == -1);
        CHECK(ml_routes_parse("1.2.3.4/24x", r, ML_MAX_ROUTES) == -1);
        CHECK(ml_routes_parse("1111.2.3.4", r, ML_MAX_ROUTES) == -1);
        CHECK(ml_routes_parse("fd00::/8", r, ML_MAX_ROUTES) == 0);       /* IPv6: not here */
        CHECK(ml_routes_parse("10.0.0.0/8, 2001:db8::/32", r, ML_MAX_ROUTES) == 1);
        /* IPv6 prefixes */
        ml_route6_t r6[ML_MAX_ROUTES];
        char s6[48];
        uint8_t a6[16];
        CHECK(ml_routes_parse6("10.0.0.0/8 2001:db8:1:2::5/64, fd12:3456::/48;fd12:3456::/48 ::/0", r6, ML_MAX_ROUTES) == 2);
        ml_routes6_format(&r6[0], s6, sizeof(s6));
        CHECK(strcmp(s6, "2001:db8:1:2::/64") == 0);                    /* host bits cleared */
        ml_routes6_format(&r6[1], s6, sizeof(s6));
        CHECK(strcmp(s6, "fd12:3456::/48") == 0);
        inet_pton(AF_INET6, "2001:db8:1:2:abcd::1", a6);
        CHECK(ml_routes6_contain(r6, 2, a6));
        inet_pton(AF_INET6, "2001:db8:1:3::1", a6);
        CHECK(!ml_routes6_contain(r6, 2, a6));
        CHECK(ml_routes_parse6("2001:db8::1", r6, ML_MAX_ROUTES) == 1 && r6[0].len == 128);
        ml_routes6_format(&r6[0], s6, sizeof(s6));
        CHECK(strcmp(s6, "2001:db8::1/128") == 0);
        CHECK(ml_routes_parse6("2001:db8::/129", r6, ML_MAX_ROUTES) == -1);
        CHECK(ml_routes_parse6("2001:db8::/0", r6, ML_MAX_ROUTES) == -1);  /* only ::/0, with 0.0.0.0/0 */
        CHECK(ml_routes_parse6("2001:zz8::/32", r6, ML_MAX_ROUTES) == -1);
        CHECK(ml_routes_parse6("192.168.1.0/24", r6, ML_MAX_ROUTES) == 0);
        CHECK(ml_routes_parse("1.0.0.0/8,2.0.0.0/8,3.0.0.0/8", r, 2) == -1);
    }

    /* Destination check: tailnet IP and advertised routes only, in every
     * mode, before any rule or bypass. */
    {
        ml_route_t r[1];
        uint8_t b[64];
        size_t n;
        CHECK(ml_routes_parse("192.168.1.0/24", r, 1) == 1);
        ml_filter_set_local(ip(ME), r, 1);
        n = pkt(b, 17, "100.64.0.6", "192.168.1.20", 1, 53, 0, 0);
        CHECK(ml_filter_check_inbound(b, n, 1000));        /* inside the route */
        n = pkt(b, 17, "100.64.0.6", "192.168.2.20", 1, 53, 0, 0);
        CHECK(!ml_filter_check_inbound(b, n, 1000));       /* outside */
        n = pkt(b, 6, "100.64.0.6", "10.0.0.1", 1, 22, ACK, 0);
        CHECK(!ml_filter_check_inbound(b, n, 1000));       /* non-SYN TCP is no way round it */
        n = pkt(b, 1, "100.64.0.6", "10.0.0.1", 0, 0, 0, 0);
        CHECK(!ml_filter_check_inbound(b, n, 1000));       /* nor an ICMP reply */
        ml_filter_init(ML_FILTER_MODE_OFF);
        CHECK(!ml_filter_check_inbound(b, n, 1000));       /* nor ACLs off */
        CHECK(in(17, "100.64.0.6", 1, 53, 0, 0));          /* own IP unaffected */
        ml_filter_init(ML_FILTER_MODE_ENFORCE);

        /* A UDP flow the device opened admits replies to the device only,
         * not to a LAN host on the same ports. */
        apply("{\"PacketFilter\":[]}");
        n = pkt(b, 17, ME, "100.64.0.7", 5000, 7000, 0, 0);
        ml_filter_note_outbound(b, n, 1000);
        CHECK(in(17, "100.64.0.7", 7000, 5000, 0, 0));
        n = pkt(b, 17, "100.64.0.7", "192.168.1.20", 7000, 5000, 0, 0);
        CHECK(!ml_filter_check_inbound(b, n, 1000));

        /* Self IP unknown: no destination check yet. */
        ml_filter_set_local(0, NULL, 0);
        apply("{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]}");
        n = pkt(b, 17, "100.64.0.6", "192.168.2.20", 1, 53, 0, 0);
        CHECK(ml_filter_check_inbound(b, n, 1000));
    }

    /* IPv6 */
    {
        uint8_t self6[16];
        inet_pton(AF_INET6, ME6, self6);
        ml_filter_reset();
        ml_filter_init(ML_FILTER_MODE_ENFORCE);
        apply("{\"PacketFilter\":" ALLOW_ALL "}");
        /* no tailnet IPv6 address yet: nothing */
        CHECK(!in6(6, "fd7a:115c:a1e0::5", ME6, 22, SYN, 0));
        ml_filter_set_local6(self6, false, NULL, 0);
        CHECK(in6(6, "fd7a:115c:a1e0::5", ME6, 22, SYN, 0));            /* "*" covers IPv6 */
        CHECK(!in6(6, "fd7a:115c:a1e0::5", "2606:4700::1111", 443, SYN, 0)); /* not an exit node */
        {   /* IPv6 subnet route */
            ml_route6_t rt6[1];
            CHECK(ml_routes_parse6("2001:db8:1::/64", rt6, 1) == 1);
            ml_filter_set_local6(self6, false, rt6, 1);
            CHECK(in6(6, "fd7a:115c:a1e0::5", "2001:db8:1::20", 22, SYN, 0));
            CHECK(!in6(6, "fd7a:115c:a1e0::5", "2001:db8:2::20", 22, SYN, 0));
            ml_filter_set_local6(self6, false, NULL, 0);
            CHECK(!in6(6, "fd7a:115c:a1e0::5", "2001:db8:1::20", 22, SYN, 0));
        }
        ml_filter_set_local6(self6, true, NULL, 0);
        CHECK(in6(6, "fd7a:115c:a1e0::5", "2606:4700::1111", 443, SYN, 0));
        CHECK(!in6(6, "fd7a:115c:a1e0::5", "fd7a:115c:a1e0::9", 22, SYN, 0)); /* other tailnet node */
        CHECK(!in6(6, "fd7a:115c:a1e0::5", "fe80::1", 22, SYN, 0));
        CHECK(!in6(6, "fd7a:115c:a1e0::5", "ff02::1", 22, SYN, 0));
        {   /* extension headers are not handled: dropped */
            uint8_t b[96];
            size_t n = pkt6(b, 6, "fd7a:115c:a1e0::5", ME6, 1, 22, SYN, 0);
            b[6] = 0;                                                      /* hop-by-hop */
            CHECK(!ml_filter_check_inbound(b, n, 1000));
            n = pkt6(b, 6, "fd7a:115c:a1e0::5", ME6, 1, 22, SYN, 0);
            b[5] = 200;                                                    /* payload length beyond the data */
            CHECK(!ml_filter_check_inbound(b, n, 1000));
        }

        /* An IPv4-only policy grants nothing over IPv6 ... */
        apply("{\"PacketFilter\":[{\"SrcIPs\":[\"100.64.0.5\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]}");
        CHECK(!in6(6, "fd7a:115c:a1e0::5", ME6, 22, SYN, 0));
        CHECK(in6(6, "fd7a:115c:a1e0::5", ME6, 22, ACK, 0));             /* non-SYN TCP */
        CHECK(in6(58, "fd7a:115c:a1e0::5", ME6, 0, 0, 129));              /* echo reply */
        CHECK(!in6(58, "fd7a:115c:a1e0::5", ME6, 0, 0, 128));             /* echo request */
        /* ... IPv6 entries do, with ports */
        apply("{\"PacketFilter\":[{\"SrcIPs\":[\"fd7a:115c:a1e0::5/128\"],\"DstPorts\":["
              "{\"IP\":\"2000::/3\",\"Ports\":{\"First\":443,\"Last\":443}},"
              "{\"IP\":\"" ME6 "\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]}");
        CHECK(in6(6, "fd7a:115c:a1e0::5", "2606:4700::1111", 443, SYN, 0));
        CHECK(!in6(6, "fd7a:115c:a1e0::5", "2606:4700::1111", 80, SYN, 0));
        CHECK(!in6(6, "fd7a:115c:a1e0::6", "2606:4700::1111", 443, SYN, 0));
        CHECK(in6(58, "fd7a:115c:a1e0::5", ME6, 0, 0, 128));              /* ICMPv6 in the default protocols */
        CHECK(!in6(6, "fd7a:115c:a1e0::5", "fc00::1", 443, SYN, 0));      /* outside 2000::/3 */
        ml_filter_set_local6(NULL, false, NULL, 0);
        CHECK(!in6(6, "fd7a:115c:a1e0::5", ME6, 22, SYN, 0));
    }

    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("all packet filter tests passed\n");
    return 0;
}
