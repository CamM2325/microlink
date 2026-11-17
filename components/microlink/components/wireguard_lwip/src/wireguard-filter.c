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

#include <limits.h>
#include <string.h>
#include "wireguard.h"
#include "wireguard-filter.h"

/*
 * Type-aware allowed-IP match.
 * Returns the prefix length of `a` if `addr` lies inside it, or -1 if not.
 * Never compares an IPv4 rule against an IPv6 address (lwIP's ip_addr_netcmp
 * will happily compare the raw union when types differ).
 */
int wg_allowed_ip_match_len(const struct wireguard_allowed_ip *a, const ip_addr_t *addr) {
	if (!a->valid) {
		return -1;
	}
#if LWIP_IPV4
	if (IP_IS_V4(addr) && IP_IS_V4(&a->ip)) {
		const uint32_t m = ip4_addr_get_u32(ip_2_ip4(&a->mask));
		if ((ip4_addr_get_u32(ip_2_ip4(addr)) & m) != (ip4_addr_get_u32(ip_2_ip4(&a->ip)) & m)) {
			return -1;
		}
		return __builtin_popcount(m);
	}
#endif
#if LWIP_IPV6
	if (IP_IS_V6(addr) && IP_IS_V6(&a->ip)) {
		int len = 0;
		for (int i = 0; i < 4; i++) {
			const uint32_t m = ip_2_ip6(&a->mask)->addr[i];
			if ((ip_2_ip6(addr)->addr[i] & m) != (ip_2_ip6(&a->ip)->addr[i] & m)) {
				return -1;
			}
			len += __builtin_popcount(m);
		}
		return len;
	}
#endif
	return -1;
}

/* Longest prefix among this peer's allowed IPs that contains `addr`, or -1. */
int wg_peer_match_len(const struct wireguard_peer *peer, const ip_addr_t *addr) {
	int best = -1;
	for (int y = 0; y < WIREGUARD_MAX_SRC_IPS; y++) {
		int len = wg_allowed_ip_match_len(&peer->allowed_source_ips[y], addr);
		if (len > best) {
			best = len;
		}
	}
	return best;
}

struct wireguard_keypair *wg_peer_tx_keypair(struct wireguard_peer *peer) {
	struct wireguard_keypair *keypair = &peer->curr_keypair;
	// We may not be able to use the current keypair if we haven't received data, may need to resort to using previous keypair
	if (keypair->valid && !keypair->initiator && (keypair->last_rx == 0)) {
		keypair = &peer->prev_keypair;
	}
	if (keypair->valid && (keypair->initiator || (keypair->last_rx != 0))) {
		return keypair;
	}
	return NULL;
}

bool wg_peer_can_send(struct wireguard_peer *peer) {
	const struct wireguard_keypair *keypair = wg_peer_tx_keypair(peer);
	return keypair &&
		!wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) &&
		(keypair->sending_counter < REJECT_AFTER_MESSAGES);
}

/*
 * Cryptokey routing (outbound): longest-prefix match across all peers.
 * A more specific route always wins — e.g. a /32 tailnet peer beats a
 * 0.0.0.0/0 exit node even when the /32 peer has no session yet (in that
 * case the packet is queued/handshake started for the correct peer rather
 * than being encrypted to the wrong one). Having a live session is only
 * used to break ties between equally specific routes, and it counts only if
 * TX can actually use it: a slot whose curr keypair expired keeps a valid
 * prev that TX never selects, and must not win the tie over a live peer
 * (e.g. the old and new node key of a peer that rotated keys, both owning
 * the same /32 until the old one is removed).
 *
 * Runs on tcpip_thread without the state lock: the session test is only a
 * preference, wireguardif_output_to_peer() re-checks under the lock.
 */
struct wireguard_peer *wg_peer_lookup_by_allowed_ip(struct wireguard_device *device, const ip_addr_t *ipaddr) {
	struct wireguard_peer *best = NULL;
	int best_len = -1;
	bool best_has_session = false;
	for (int x = 0; x < WIREGUARD_MAX_PEERS; x++) {
		struct wireguard_peer *tmp = &device->peers[x];
		if (!tmp->valid) {
			continue;
		}
		int len = wg_peer_match_len(tmp, ipaddr);
		if (len < 0) {
			continue;
		}
		bool has_session = wg_peer_can_send(tmp);
		if (len > best_len || (len == best_len && has_session && !best_has_session)) {
			best = tmp;
			best_len = len;
			best_has_session = has_session;
		}
	}
	return best;
}

/*
 * Cryptokey routing (inbound): a decrypted packet from `peer` is only accepted
 * if its inner source address is inside one of `peer`'s allowed IPs AND no
 * other peer owns a strictly more specific route for that address. This stops
 * a peer that holds a broad route (e.g. 0.0.0.0/0 exit node) from spoofing the
 * tailnet address of another peer.
 */
bool wg_peer_allowed_source(struct wireguard_device *device, const struct wireguard_peer *peer, const ip_addr_t *src) {
	int own = wg_peer_match_len(peer, src);
	if (own < 0) {
		return false;
	}
	for (int x = 0; x < WIREGUARD_MAX_PEERS; x++) {
		const struct wireguard_peer *other = &device->peers[x];
		if (other == peer || !other->valid) {
			continue;
		}
		if (wg_peer_match_len(other, src) > own) {
			return false;
		}
	}
	return true;
}

bool wireguard_check_replay(struct wireguard_keypair *keypair, uint64_t seq) {
	// Sliding-window replay filter (RFC 2401 Appendix C / RFC 6479 style).
	// The window is 64 packets wide; differences are computed in 64 bits so a
	// huge counter jump can never alias back into the window.
	const uint64_t ReplayWindowSize = sizeof(keypair->replay_bitmap) * CHAR_BIT; // 64 bits
	uint64_t diff;
	bool result = false;

	// WireGuard data packet counter starts from 0 but algorithm expects packet numbers to start from 1
	seq++;

	if (seq == 0) {
		// counter wrapped - never valid
		return false;
	}
	if (seq > keypair->replay_counter) {
		// new larger sequence number
		diff = seq - keypair->replay_counter;
		if (diff < ReplayWindowSize) {
			keypair->replay_bitmap <<= diff;
			keypair->replay_bitmap |= 1;
		} else {
			keypair->replay_bitmap = 1;
		}
		keypair->replay_counter = seq;
		result = true;
	} else {
		diff = keypair->replay_counter - seq;
		if (diff < ReplayWindowSize) {
			const uint64_t bit = (uint64_t)1 << diff;
			if ((keypair->replay_bitmap & bit) == 0) {
				// out of order but not seen before
				keypair->replay_bitmap |= bit;
				result = true;
			}
		}
		// else: too old
	}
	return result;
}

bool wg_endpoint_ip4_is_valid_underlay(uint32_t ip_host_order) {
	const uint32_t a = ip_host_order;
	if ((a >> 24) == 0 || (a >> 24) == 127) return false;          /* 0/8, loopback */
	if ((a & 0xFFC00000u) == 0x64400000u) return false;            /* 100.64/10 tailnet (CGNAT) */
	if ((a & 0xFFFF0000u) == 0xA9FE0000u) return false;            /* 169.254/16 link-local */
	if ((a >> 28) >= 0xE) return false;                             /* multicast, reserved, broadcast */
	return true;
}

bool wg_endpoint_is_valid_underlay(const ip_addr_t *addr) {
#if LWIP_IPV4
	if (IP_IS_V4(addr)) {
		return wg_endpoint_ip4_is_valid_underlay(PP_NTOHL(ip4_addr_get_u32(ip_2_ip4(addr))));
	}
#endif
#if LWIP_IPV6
	if (IP_IS_V6(addr)) {
		const uint32_t w0 = PP_NTOHL(ip_2_ip6(addr)->addr[0]);
		const uint32_t w1 = PP_NTOHL(ip_2_ip6(addr)->addr[1]);
		const uint32_t w2 = PP_NTOHL(ip_2_ip6(addr)->addr[2]);
		if (w0 == 0xfd7a115cu && (w1 >> 16) == 0xa1e0u) return false;  /* fd7a:115c:a1e0::/48 tailnet */
		if ((w0 >> 24) == 0xff) return false;                          /* multicast */
		if ((w0 & 0xffc00000u) == 0xfe800000u) return false;           /* fe80::/10 link-local */
		/* ::/96 (unspecified, loopback, deprecated IPv4-compatible) and
		 * ::ffff:0:0/96 (IPv4-mapped): an embedded IPv4 address would bypass
		 * the IPv4 checks above (e.g. ::ffff:100.64.0.1 or ::ffff:127.0.0.1). */
		if (w0 == 0 && w1 == 0 && (w2 == 0 || w2 == 0x0000ffffu)) return false;
		return true;
	}
#endif
	return false;
}
