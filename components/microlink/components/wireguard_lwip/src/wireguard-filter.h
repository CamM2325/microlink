/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * Copyright (c) 2026 MicroLink contributors
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Security-critical packet filters for wireguard-lwip, split out so they can
 * be unit-tested on a host PC without hardware (see test/host/).
 *   - cryptokey routing (outbound longest-prefix peer selection)
 *   - inbound inner-source validation
 *   - anti-replay sliding window
 */

#ifndef _WIREGUARD_FILTER_H_
#define _WIREGUARD_FILTER_H_

#include <stdbool.h>
#include "wireguard.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Prefix length of `a` if `addr` is inside it (type-aware v4/v6), else -1. */
int wg_allowed_ip_match_len(const struct wireguard_allowed_ip *a, const ip_addr_t *addr);

/* Longest prefix among `peer`'s allowed IPs containing `addr`, else -1. */
int wg_peer_match_len(const struct wireguard_peer *peer, const ip_addr_t *addr);

/*
 * The keypair transport data to `peer` is encrypted with: curr, or prev while
 * curr is a responder keypair the initiator has not confirmed yet (no data
 * received on it). NULL if neither can send. Expiry and the message limit are
 * not checked here. The caller serialises against keypair changes.
 */
struct wireguard_keypair *wg_peer_tx_keypair(struct wireguard_peer *peer);

/*
 * True if `peer` has a keypair transport data can be sent with right now:
 * wg_peer_tx_keypair() is non-NULL, not past Reject-After-Time and below the
 * message limit. This is what "session up" means for TX.
 */
bool wg_peer_can_send(struct wireguard_peer *peer);

/* Outbound cryptokey routing: longest-prefix match; a usable session
 * (wg_peer_can_send) only breaks ties. */
struct wireguard_peer *wg_peer_lookup_by_allowed_ip(struct wireguard_device *device, const ip_addr_t *ipaddr);

/* Inbound: true iff inner source `src` routes back to `peer` (no more-specific owner). */
bool wg_peer_allowed_source(struct wireguard_device *device, const struct wireguard_peer *peer, const ip_addr_t *src);

/*
 * A peer endpoint must be a real underlay address. Tunnel-internal (tailnet
 * 100.64.0.0/10, fd7a:115c:a1e0::/48), loopback, unspecified, link-local
 * (169.254/16, fe80::/10), multicast and broadcast addresses are rejected: an
 * endpoint inside the tunnel makes every encrypted packet loop back into the
 * WireGuard netif (unbounded recursion -> stack overflow, triggerable by any
 * tailnet peer). IPv4-mapped/compatible IPv6 (::ffff:0:0/96, ::/96) is
 * rejected too, since it would hide an IPv4 address from the IPv4 checks.
 *
 * Note: wireguardif's output paths are IPv4-only, so it additionally refuses
 * every IPv6 endpoint (see wireguardif.c) until an IPv6 underlay exists.
 */
bool wg_endpoint_is_valid_underlay(const ip_addr_t *addr);
bool wg_endpoint_ip4_is_valid_underlay(uint32_t ip_host_order);

/* wireguard_check_replay() is declared in wireguard.h and implemented in wireguard-filter.c */

#ifdef __cplusplus
}
#endif

#endif /* _WIREGUARD_FILTER_H_ */
