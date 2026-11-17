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

/* Parse a list of IPv4 CIDRs separated by commas, spaces, semicolons or
 * newlines ("192.168.1.0/24, 10.0.0.0/8"). A bare address means /32.
 * Host bits are cleared ("192.168.1.5/24" becomes 192.168.1.0/24).
 * "::/0" is accepted and ignored: an exit node is requested with
 * "0.0.0.0/0", which the device advertises together with "::/0" itself.
 * Duplicates are dropped. Returns the number of routes stored, or -1 if an
 * entry is not a valid IPv4 CIDR, is an IPv6 prefix other than "::/0", or
 * there are more than max. NULL or an empty list gives 0. */
int ml_routes_parse(const char *list, ml_route_t *out, int max);

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
