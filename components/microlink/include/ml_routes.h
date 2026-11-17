/*
 * ml_routes: the subnet routes a device advertises to the tailnet
 * (Hostinfo.RoutableIPs), as used by a subnet router or exit node.
 *
 * Pure C with no ESP-IDF dependency, so the host tests can cover it.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ML_MAX_ROUTES 8

typedef struct {
    uint32_t net;   /* network address, host byte order, host bits zero */
    uint8_t  len;   /* prefix length 0..32 */
} ml_route_t;

typedef struct {
    uint8_t net[16];   /* network address, host bits zero */
    uint8_t len;       /* prefix length 1..128 */
} ml_route6_t;

/* Parse the IPv4 CIDRs of a list separated by commas, spaces, semicolons or
 * newlines ("192.168.1.0/24, 10.0.0.0/8, fd12:3456::/64"). A bare address
 * means /32. Host bits are cleared ("192.168.1.5/24" becomes
 * 192.168.1.0/24). IPv6 entries are skipped (ml_routes_parse6() takes
 * them); "::/0" is ignored too: an exit node is requested with "0.0.0.0/0",
 * which the device advertises together with "::/0" itself. Duplicates are
 * dropped. Returns the number of routes stored, or -1 if an IPv4 entry is
 * invalid or there are more than max. NULL or an empty list gives 0. */
int ml_routes_parse(const char *list, ml_route_t *out, int max);

/* The IPv6 prefixes of the same list ("2001:db8:1::/64"; a bare address is
 * /128; host bits cleared; "::/0" ignored as above). Returns the number
 * stored, or -1 if an IPv6 entry is invalid or there are more than max. */
int ml_routes_parse6(const char *list, ml_route6_t *out, int max);

/* True if ip (16 bytes, network order) is inside one of the prefixes. */
bool ml_routes6_contain(const ml_route6_t *routes, int n, const uint8_t ip[16]);

/* Format one IPv6 prefix as "addr/len" (RFC 5952). buf needs 44 bytes. */
void ml_routes6_format(const ml_route6_t *route, char *buf, size_t size);

/* True if the routes include 0.0.0.0/0 (the device offers itself as an
 * exit node). */
bool ml_routes_is_exit_node(const ml_route_t *routes, int n);

/* True if ip (host byte order) is inside one of the routes. */
bool ml_routes_contain(const ml_route_t *routes, int n, uint32_t ip);

/* Format one route as "a.b.c.d/len". buf needs 19 bytes. */
void ml_routes_format(const ml_route_t *route, char *buf, size_t size);

#ifdef __cplusplus
}
#endif
