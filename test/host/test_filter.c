/* Host tests for ml_filter (tailnet packet filter / ACL enforcement). */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "ml_filter.h"

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
    if (proto == 1) { b[20] = icmp_type; return 28; }
    b[20] = (uint8_t)(sport >> 8); b[21] = (uint8_t)sport; b[22] = (uint8_t)(dport >> 8); b[23] = (uint8_t)dport;
    if (proto == 6) { b[33] = tcp_flags; return 40; }
    return 28;
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

    /* Before any policy: accept. */
    CHECK(in(17, "100.64.0.9", 1234, 22, 0, 0));

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

    /* Reset clears policy. */
    ml_filter_reset();
    ml_filter_init(ML_FILTER_MODE_ENFORCE);
    CHECK(in(17, "100.64.0.6", 1, 53, 0, 0));

    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("all packet filter tests passed\n");
    return 0;
}
