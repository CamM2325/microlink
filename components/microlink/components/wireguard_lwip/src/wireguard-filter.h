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

/* Outbound cryptokey routing: longest-prefix match; session only breaks ties. */
struct wireguard_peer *wg_peer_lookup_by_allowed_ip(struct wireguard_device *device, const ip_addr_t *ipaddr);

/* Inbound: true iff inner source `src` routes back to `peer` (no more-specific owner). */
bool wg_peer_allowed_source(struct wireguard_device *device, const struct wireguard_peer *peer, const ip_addr_t *src);

/* wireguard_check_replay() is declared in wireguard.h and implemented in wireguard-filter.c */

#ifdef __cplusplus
}
#endif

#endif /* _WIREGUARD_FILTER_H_ */
