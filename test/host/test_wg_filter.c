/*
 * Regression tests for wireguard-lwip packet filters (no hardware needed).
 * Covers the issues fixed in the Nov 2026 security release:
 *   1. TX: more-specific peer must win over a broader peer that has a session
 *   2. RX: a peer holding 0.0.0.0/0 must not be able to spoof another peer's IP
 *      (and IPv4 rules must never match IPv6 addresses)
 *   3. Anti-replay window (endpoint/state updates are gated on it)
 *   4. TX keypair selection and the "usable session" route tie-break
 */
#include <stdio.h>
#include <string.h>
#include "wireguard.h"
#include "wireguard-filter.h"

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static struct wireguard_device dev;

/* wireguard_expired() lives in wireguard.c (platform clock); a fake clock is
 * enough here. Same arithmetic as the real one. */
static uint32_t fake_now_ms = 1000000;
bool wireguard_expired(uint32_t created_millis, uint32_t valid_seconds) {
	return (uint32_t)(fake_now_ms - created_millis) >= valid_seconds * 1000;
}

static void v4(ip_addr_t *out, int a, int b, int c, int d) {
	IP_ADDR4(out, a, b, c, d);
}

static void v6(ip_addr_t *out, uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3) {
	IP_ADDR6(out, __builtin_bswap32(w0), __builtin_bswap32(w1), __builtin_bswap32(w2), __builtin_bswap32(w3)); /* host is little-endian */
}

static struct wireguard_peer *add_peer(int idx, const ip_addr_t *ip, const ip_addr_t *mask, bool session) {
	struct wireguard_peer *p = &dev.peers[idx];
	memset(p, 0, sizeof(*p));
	p->valid = true;
	p->allowed_source_ips[0].valid = true;
	p->allowed_source_ips[0].ip = *ip;
	p->allowed_source_ips[0].mask = *mask;
	p->curr_keypair.valid = session;
	p->curr_keypair.initiator = session;
	p->curr_keypair.keypair_millis = fake_now_ms;
	return p;
}

static void test_tx_longest_prefix(void) {
	memset(&dev, 0, sizeof(dev));
	ip_addr_t any, any_mask, host, host_mask, dst;
	v4(&any, 0, 0, 0, 0);       v4(&any_mask, 0, 0, 0, 0);
	v4(&host, 100, 64, 0, 7);   v4(&host_mask, 255, 255, 255, 255);

	/* exit node first in the table and HAS a session; /32 peer has none */
	struct wireguard_peer *exit_node = add_peer(0, &any, &any_mask, true);
	struct wireguard_peer *target    = add_peer(1, &host, &host_mask, false);

	v4(&dst, 100, 64, 0, 7);
	CHECK(wg_peer_lookup_by_allowed_ip(&dev, &dst) == target);   /* was exit_node before fix */

	v4(&dst, 8, 8, 8, 8);
	CHECK(wg_peer_lookup_by_allowed_ip(&dev, &dst) == exit_node);

	/* tie on equal prefix: prefer the peer with a session */
	struct wireguard_peer *dup = add_peer(2, &host, &host_mask, true);
	v4(&dst, 100, 64, 0, 7);
	CHECK(wg_peer_lookup_by_allowed_ip(&dev, &dst) == dup);

	/* IPv6 destination must never match an IPv4 0.0.0.0/0 rule */
	ip_addr_t d6;
	v6(&d6, 0xfd7a115c, 0xa1e00000, 0, 0x1);
	CHECK(wg_peer_lookup_by_allowed_ip(&dev, &d6) == NULL);
}

static void test_tx_keypair_selection(void) {
	struct wireguard_peer p;
	memset(&p, 0, sizeof(p));
	CHECK(wg_peer_tx_keypair(&p) == NULL);
	CHECK(!wg_peer_can_send(&p));

	/* initiator keypair: usable at once */
	p.curr_keypair.valid = true;
	p.curr_keypair.initiator = true;
	p.curr_keypair.keypair_millis = fake_now_ms;
	CHECK(wg_peer_tx_keypair(&p) == &p.curr_keypair);
	CHECK(wg_peer_can_send(&p));

	/* expired or exhausted: selected, but not sendable */
	p.curr_keypair.keypair_millis = fake_now_ms - REJECT_AFTER_TIME * 1000;
	CHECK(!wg_peer_can_send(&p));
	p.curr_keypair.keypair_millis = fake_now_ms;
	p.curr_keypair.sending_counter = REJECT_AFTER_MESSAGES;
	CHECK(!wg_peer_can_send(&p));
	p.curr_keypair.sending_counter = 0;

	/* unconfirmed responder keypair in curr: TX falls back to prev */
	p.curr_keypair.initiator = false;
	p.curr_keypair.last_rx = 0;
	CHECK(wg_peer_tx_keypair(&p) == NULL);
	p.prev_keypair.valid = true;
	p.prev_keypair.initiator = true;
	p.prev_keypair.keypair_millis = fake_now_ms;
	CHECK(wg_peer_tx_keypair(&p) == &p.prev_keypair);
	/* confirmed by the initiator's first data packet: curr again */
	p.curr_keypair.last_rx = fake_now_ms;
	CHECK(wg_peer_tx_keypair(&p) == &p.curr_keypair);

	/* curr destroyed, prev still valid: TX uses curr, so nothing is sendable
	 * (the state an old, rotated-out node key ends up in) */
	memset(&p.curr_keypair, 0, sizeof(p.curr_keypair));
	CHECK(p.prev_keypair.valid);
	CHECK(wg_peer_tx_keypair(&p) == NULL);
	CHECK(!wg_peer_can_send(&p));
}

static void test_tx_tie_break_needs_usable_session(void) {
	memset(&dev, 0, sizeof(dev));
	ip_addr_t host, m32, dst;
	v4(&host, 100, 64, 0, 9);   v4(&m32, 255, 255, 255, 255);

	/* Same /32 twice (old and new node key after a rotation). The old slot
	 * comes first and only has a stale prev keypair left. */
	struct wireguard_peer *old_key = add_peer(0, &host, &m32, false);
	old_key->prev_keypair.valid = true;
	old_key->prev_keypair.initiator = true;
	old_key->prev_keypair.keypair_millis = fake_now_ms - 10 * 1000;
	struct wireguard_peer *new_key = add_peer(1, &host, &m32, true);

	v4(&dst, 100, 64, 0, 9);
	CHECK(wg_peer_lookup_by_allowed_ip(&dev, &dst) == new_key);   /* was old_key */

	/* neither usable: first match, as before */
	memset(&new_key->curr_keypair, 0, sizeof(new_key->curr_keypair));
	CHECK(wg_peer_lookup_by_allowed_ip(&dev, &dst) == old_key);

	/* an expired session does not win the tie either */
	new_key->curr_keypair.valid = true;
	new_key->curr_keypair.initiator = true;
	new_key->curr_keypair.keypair_millis = fake_now_ms - REJECT_AFTER_TIME * 1000;
	CHECK(wg_peer_lookup_by_allowed_ip(&dev, &dst) == old_key);
}

static void test_rx_source_validation(void) {
	memset(&dev, 0, sizeof(dev));
	ip_addr_t any, any_mask, a, b, m32, src;
	v4(&any, 0, 0, 0, 0);     v4(&any_mask, 0, 0, 0, 0);
	v4(&a, 100, 64, 0, 1);    v4(&b, 100, 64, 0, 2);   v4(&m32, 255, 255, 255, 255);

	struct wireguard_peer *exit_node = add_peer(0, &any, &any_mask, true);
	struct wireguard_peer *peer_a    = add_peer(1, &a, &m32, true);
	struct wireguard_peer *peer_b    = add_peer(2, &b, &m32, true);

	/* exit node may source internet addresses... */
	v4(&src, 1, 1, 1, 1);
	CHECK(wg_peer_allowed_source(&dev, exit_node, &src));
	/* ...but must NOT impersonate peer A's tailnet address */
	CHECK(!wg_peer_allowed_source(&dev, exit_node, &a));
	/* peers may only source their own address */
	CHECK(wg_peer_allowed_source(&dev, peer_a, &a));
	CHECK(!wg_peer_allowed_source(&dev, peer_a, &b));
	CHECK(!wg_peer_allowed_source(&dev, peer_b, &src));

	/* inner IPv6 is not covered by any IPv4 rule -> dropped */
	ip_addr_t s6;
	v6(&s6, 0xfd7a115c, 0xa1e00000, 0, 0x2);
	CHECK(!wg_peer_allowed_source(&dev, exit_node, &s6));
	CHECK(!wg_peer_allowed_source(&dev, peer_a, &s6));

	/* IPv6 rule works when present */
	ip_addr_t p6, m128;
	v6(&p6, 0xfd7a115c, 0xa1e00000, 0, 0x2);
	v6(&m128, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);
	peer_b->allowed_source_ips[1].valid = true;
	peer_b->allowed_source_ips[1].ip = p6;
	peer_b->allowed_source_ips[1].mask = m128;
	CHECK(wg_peer_allowed_source(&dev, peer_b, &s6));
	CHECK(!wg_peer_allowed_source(&dev, peer_a, &s6));
}

static void test_replay_window(void) {
	struct wireguard_keypair kp;
	memset(&kp, 0, sizeof(kp));

	CHECK(wireguard_check_replay(&kp, 0));
	CHECK(!wireguard_check_replay(&kp, 0));           /* exact replay */
	CHECK(wireguard_check_replay(&kp, 5));
	CHECK(wireguard_check_replay(&kp, 3));            /* out of order, first time */
	CHECK(!wireguard_check_replay(&kp, 3));           /* replay of reordered pkt */
	CHECK(wireguard_check_replay(&kp, 100));
	CHECK(wireguard_check_replay(&kp, 100 - 63));     /* edge of 64-wide window */
	CHECK(!wireguard_check_replay(&kp, 100 - 64));    /* just outside window */
	CHECK(!wireguard_check_replay(&kp, 5));           /* old */

	/* 64-bit counter jump must not alias back into the window */
	memset(&kp, 0, sizeof(kp));
	CHECK(wireguard_check_replay(&kp, 10));
	CHECK(wireguard_check_replay(&kp, 10 + (1ULL << 32)));
	CHECK(!wireguard_check_replay(&kp, 10 + 2));      /* far below new counter */
	CHECK(!wireguard_check_replay(&kp, UINT64_MAX));  /* wraps to 0 -> invalid */
}

static void test_underlay_endpoints(void) {
	ip_addr_t a;
	v4(&a, 203, 0, 113, 5);    CHECK(wg_endpoint_is_valid_underlay(&a));
	v4(&a, 192, 168, 1, 20);   CHECK(wg_endpoint_is_valid_underlay(&a));
	v4(&a, 100, 64, 0, 1);     CHECK(!wg_endpoint_is_valid_underlay(&a));   /* tailnet: tunnel loop */
	v4(&a, 100, 127, 255, 1);  CHECK(!wg_endpoint_is_valid_underlay(&a));
	v4(&a, 100, 128, 0, 1);    CHECK(wg_endpoint_is_valid_underlay(&a));    /* outside /10 */
	v4(&a, 127, 0, 0, 1);      CHECK(!wg_endpoint_is_valid_underlay(&a));
	v4(&a, 255, 255, 255, 255);CHECK(!wg_endpoint_is_valid_underlay(&a));
	v4(&a, 224, 0, 0, 1);      CHECK(!wg_endpoint_is_valid_underlay(&a));
	v4(&a, 169, 254, 1, 1);    CHECK(!wg_endpoint_is_valid_underlay(&a));
	v6(&a, 0xfd7a115c, 0xa1e00000, 0, 1);  CHECK(!wg_endpoint_is_valid_underlay(&a));
	v6(&a, 0x20010db8, 0, 0, 1);           CHECK(wg_endpoint_is_valid_underlay(&a));
	v6(&a, 0, 0, 0, 1);                    CHECK(!wg_endpoint_is_valid_underlay(&a));   /* ::1 */
}

int main(void) {
	test_tx_longest_prefix();
	test_tx_keypair_selection();
	test_tx_tie_break_needs_usable_session();
	test_rx_source_validation();
	test_replay_window();
	test_underlay_endpoints();
	if (failures) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	printf("all wg filter tests passed\n");
	return 0;
}
