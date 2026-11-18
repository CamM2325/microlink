/*
 * Regression test for endpoint roaming on the WireGuard receive path
 * (GHSA-jxrh-hg4w-g4rm, issue #44). No hardware needed.
 *
 * Two real wireguardif instances ("device" and "server") talk over a wire
 * that is an array in this file: whatever one side hands to its UDP output
 * callback, the test delivers to the other side's wireguardif_network_rx()
 * from a source address the test picks. Handshake, AEAD and the receive path
 * are the component's own code; only lwIP's pbuf/mem calls, the platform
 * clock and the RNG are stand-ins.
 *
 * What must hold on the device:
 *   1. A cookie reply never moves the peer endpoint (it can be built from
 *      public data alone).
 *   2. A captured transport packet re-sent from another address changes
 *      nothing: not the endpoint, not last_rx, not the keypairs.
 *   3. Roaming still works: a fresh authentic packet from a new address
 *      moves the endpoint there.
 *   4. A replayed keep-alive changes nothing.
 *   5. A packet that fails authentication changes nothing, whatever counter
 *      it claims, and does not block the next authentic packet.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/pbuf.h"
#include "lwip/mem.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"

#include "wireguardif.h"
#include "wireguard.h"
#include "crypto.h"

/* The receive entry point: not in wireguardif.h, the component's callers
 * declare it themselves. */
void wireguardif_network_rx(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)
/* Setup steps the rest of the test depends on */
#define REQUIRE(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s (cannot continue)\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)

/* ---- platform stand-ins (wireguard-platform.h) ---- */

static uint32_t clock_ms = 100000;
static uint32_t rng_state = 0x2468ace1u;

uint32_t wireguard_sys_now(void) { return clock_ms; }
bool wireguard_is_under_load(void) { return false; }
void wireguard_random_bytes(void *bytes, size_t size) {
	uint8_t *p = bytes;
	while (size--) {
		rng_state ^= rng_state << 13;
		rng_state ^= rng_state >> 17;
		rng_state ^= rng_state << 5;
		*p++ = (uint8_t)rng_state;
	}
}
void wireguard_tai64n_now(uint8_t *output) {
	static uint32_t stamp = 1;
	U64TO8_BIG(output, 0x400000000000000aULL + 1800000000ULL);
	U32TO8_BIG(output + 8, stamp);
	stamp++;
}

/* ---- lwIP stand-ins: just enough pbuf and heap for wireguardif.c ---- */

static int live_pbufs = 0;
static int live_blocks = 0;

struct pbuf *pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type) {
	(void)layer; (void)type;
	struct pbuf *p = calloc(1, sizeof(*p));
	REQUIRE(p != NULL);
	/* Payload in its own allocation, exactly 'length' long, so that
	 * AddressSanitizer sees any read or write past the packet. */
	p->payload = calloc(1, length ? length : 1);
	REQUIRE(p->payload != NULL);
	p->len = p->tot_len = length;
	p->ref = 1;
	live_pbufs++;
	return p;
}
u8_t pbuf_free(struct pbuf *p) {
	free(p->payload);
	free(p);
	live_pbufs--;
	return 1;
}
err_t pbuf_take(struct pbuf *buf, const void *dataptr, u16_t len) {
	if (len > buf->tot_len) return ERR_ARG;
	memcpy(buf->payload, dataptr, len);
	return ERR_OK;
}
u16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, u16_t len, u16_t offset) {
	if (offset >= p->tot_len) return 0;
	if (len > p->tot_len - offset) len = (u16_t)(p->tot_len - offset);
	memcpy(dataptr, (const uint8_t *)p->payload + offset, len);
	return len;
}
void *mem_malloc(mem_size_t size) { live_blocks++; return malloc(size); }
void *mem_calloc(mem_size_t count, mem_size_t size) { live_blocks++; return calloc(count, size); }
void mem_free(void *mem) { live_blocks--; free(mem); }

void netif_set_link_up(struct netif *netif) { netif->flags |= NETIF_FLAG_LINK_UP; }
void netif_set_link_down(struct netif *netif) { netif->flags &= (u8_t)~NETIF_FLAG_LINK_UP; }

/* The tests run in magicsock mode (no internal socket, no lwIP timer), so
 * none of these may be reached. */
#ifdef sys_timeout
#undef sys_timeout
void sys_timeout_debug(u32_t msecs, sys_timeout_handler handler, void *arg, const char *name) { (void)msecs; (void)handler; (void)arg; (void)name; abort(); }
#else
void sys_timeout(u32_t msecs, sys_timeout_handler handler, void *arg) { (void)msecs; (void)handler; (void)arg; abort(); }
#endif
void sys_untimeout(sys_timeout_handler handler, void *arg) { (void)handler; (void)arg; }
struct udp_pcb *udp_new(void) { abort(); }
err_t udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port) { (void)pcb; (void)ipaddr; (void)port; abort(); }
void udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif) { (void)pcb; (void)netif; abort(); }
void udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg) { (void)pcb; (void)recv; (void)recv_arg; abort(); }
void udp_remove(struct udp_pcb *pcb) { (void)pcb; abort(); }
err_t udp_sendto(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip, u16_t dst_port) { (void)pcb; (void)p; (void)dst_ip; (void)dst_port; abort(); }

/* From lwIP's ip.c and def.c, which the host tests do not build */
const ip_addr_t ip_addr_any = IPADDR4_INIT(IPADDR_ANY);
#ifndef lwip_htonl
u32_t lwip_htonl(u32_t n) { return PP_HTONL(n); }
u16_t lwip_htons(u16_t n) { return PP_HTONS(n); }
#endif

/* Only log lines read these */
char *ipaddr_ntoa_r(const ip_addr_t *addr, char *buf, int buflen) {
	if (IP_IS_V4(addr)) {
		const uint8_t *b = (const uint8_t *)&ip_2_ip4(addr)->addr;
		snprintf(buf, (size_t)buflen, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
	} else {
		snprintf(buf, (size_t)buflen, "(ipv6)");
	}
	return buf;
}
char *ipaddr_ntoa(const ip_addr_t *addr) {
	static char buf[IPADDR_STRLEN_MAX];
	return ipaddr_ntoa_r(addr, buf, sizeof(buf));
}

/* ---- the two ends and the wire between them ---- */

struct side {
	struct netif netif;
	struct wireguard_device *dev;
	char private_key_b64[48];
	/* What this side's IP layer received from the tunnel */
	unsigned delivered;
	/* The last datagram this side sent, and where to */
	uint8_t wire[256];
	size_t wire_len;
	ip_addr_t wire_ip;
	uint16_t wire_port;
	unsigned sent;
};

static struct side device_side, server_side;

static err_t capture_udp(uint32_t dest_ip, uint16_t dest_port, const uint8_t *data, size_t len, void *ctx) {
	struct side *s = ctx;
	REQUIRE(len <= sizeof(s->wire));
	memcpy(s->wire, data, len);
	s->wire_len = len;
	ip_addr_set_ip4_u32(&s->wire_ip, dest_ip);
	s->wire_port = dest_port;
	s->sent++;
	return ERR_OK;
}

static err_t tunnel_input(struct pbuf *p, struct netif *inp) {
	struct side *s = (inp == &device_side.netif) ? &device_side : &server_side;
	s->delivered++;
	pbuf_free(p);
	return ERR_OK;
}

static void base64(const uint8_t *in, size_t len, char *out) {
	static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i;
	for (i = 0; i + 2 < len; i += 3) {
		uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
		*out++ = tbl[v >> 18]; *out++ = tbl[(v >> 12) & 63]; *out++ = tbl[(v >> 6) & 63]; *out++ = tbl[v & 63];
	}
	if (len - i == 2) {
		uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
		*out++ = tbl[v >> 18]; *out++ = tbl[(v >> 12) & 63]; *out++ = tbl[(v >> 6) & 63]; *out++ = '=';
	} else if (len - i == 1) {
		uint32_t v = (uint32_t)in[i] << 16;
		*out++ = tbl[v >> 18]; *out++ = tbl[(v >> 12) & 63]; *out++ = '='; *out++ = '=';
	}
	*out = '\0';
}

static void side_up(struct side *s, u16_t listen_port) {
	uint8_t private_key[WIREGUARD_PRIVATE_KEY_LEN];
	struct wireguardif_init_data init = {0};

	memset(s, 0, sizeof(*s));
	wireguard_random_bytes(private_key, sizeof(private_key));
	base64(private_key, sizeof(private_key), s->private_key_b64);
	init.private_key = s->private_key_b64;
	init.listen_port = listen_port;
	s->netif.state = &init;
	REQUIRE(wireguardif_init(&s->netif) == ERR_OK);
	s->dev = s->netif.state;
	s->netif.input = tunnel_input;
	wireguardif_set_udp_output(&s->netif, capture_udp, s);
}

static u8_t add_peer(struct side *s, const struct side *other, int tunnel_host, const ip_addr_t *endpoint, u16_t port) {
	char public_key_b64[48];
	struct wireguardif_peer peer;
	u8_t index = WIREGUARDIF_INVALID_INDEX;

	base64(other->dev->public_key, WIREGUARD_PUBLIC_KEY_LEN, public_key_b64);
	wireguardif_peer_init(&peer);
	peer.public_key = public_key_b64;
	IP_ADDR4(&peer.allowed_ip, 100, 64, 0, tunnel_host);
	IP_ADDR4(&peer.allowed_mask, 255, 255, 255, 255);
	if (endpoint) {
		peer.endpoint_ip = *endpoint;
		peer.endport_port = port;
	}
	peer.keep_alive = 25;
	REQUIRE(wireguardif_add_peer(&s->netif, &peer, &index) == ERR_OK);
	REQUIRE(index != WIREGUARDIF_INVALID_INDEX);
	return index;
}

/* Hand 'len' bytes to a side as a datagram from addr:port */
static void deliver(struct side *to, const uint8_t *bytes, size_t len, const ip_addr_t *addr, u16_t port) {
	struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
	memcpy(p->payload, bytes, len);
	wireguardif_network_rx(to->dev, NULL, p, addr, port); /* frees p */
}

/* Underlay addresses. The device sits behind DEVICE_ADDR, the server is
 * configured at SERVER_ADDR; OTHER_ADDR is a third host that can only see
 * and re-send packets, and ROAMED_ADDR is where the server moves to. */
static ip_addr_t DEVICE_ADDR, SERVER_ADDR, OTHER_ADDR, ROAMED_ADDR;
#define DEVICE_PORT 41641
#define SERVER_PORT 41641
#define OTHER_PORT  4444
#define ROAMED_PORT 5555

static u8_t server_index_on_device;

static struct wireguard_peer *server_on_device(void) {
	return peer_lookup_by_peer_index(device_side.dev, server_index_on_device);
}

static bool device_endpoint_is(const ip_addr_t *addr, u16_t port) {
	ip_addr_t ip;
	u16_t current_port = 0;
	ip_addr_set_any(0, &ip);
	(void)wireguardif_peer_is_up(&device_side.netif, server_index_on_device, &ip, &current_port);
	return ip_addr_cmp(&ip, addr) && current_port == port;
}

/* The server sends one tunnel packet to the device; the encrypted datagram
 * ends up in server_side.wire. */
static void server_sends_data(void) {
	uint8_t inner[28] = {0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0,
	                     100, 64, 0, 2,   /* source: the server's tunnel address */
	                     100, 64, 0, 1};  /* destination: the device */
	ip4_addr_t dst;
	struct pbuf *q = pbuf_alloc(PBUF_RAW, sizeof(inner), PBUF_RAM);
	unsigned before = server_side.sent;

	memcpy(q->payload, inner, sizeof(inner));
	IP4_ADDR(&dst, 100, 64, 0, 1);
	REQUIRE(server_side.netif.output(&server_side.netif, q, &dst) == ERR_OK);
	pbuf_free(q);
	REQUIRE(server_side.sent == before + 1);
	REQUIRE(server_side.wire[0] == MESSAGE_TRANSPORT_DATA);
}

static void test_cookie_reply_does_not_roam(void) {
	/* The device has just sent its initiation: sender index and mac1 are
	 * readable on the wire, the server's public key is public. That is all
	 * a cookie reply needs. */
	struct message_handshake_initiation seen;
	struct message_cookie_reply forged;
	struct wireguard_peer *peer = server_on_device();
	uint8_t label_cookie_key[WIREGUARD_SESSION_KEY_LEN];
	uint8_t cookie[WIREGUARD_COOKIE_LEN] = {1, 2, 3};
	uint8_t wrong_mac1[WIREGUARD_COOKIE_LEN];
	wireguard_blake2s_ctx ctx;
	int i;

	REQUIRE(device_side.wire_len == sizeof(seen));
	memcpy(&seen, device_side.wire, sizeof(seen));

	wireguard_blake2s_init(&ctx, WIREGUARD_SESSION_KEY_LEN, NULL, 0);
	wireguard_blake2s_update(&ctx, (const uint8_t *)"cookie--", 8);
	wireguard_blake2s_update(&ctx, server_side.dev->public_key, WIREGUARD_PUBLIC_KEY_LEN);
	wireguard_blake2s_final(&ctx, label_cookie_key);

	memset(&forged, 0, sizeof(forged));
	forged.type = MESSAGE_COOKIE_REPLY;
	forged.receiver = seen.sender;
	for (i = 0; i < COOKIE_NONCE_LEN; i++) forged.nonce[i] = (uint8_t)(i * 7);

	/* Wrong mac1: rejected by the cookie check itself */
	memset(wrong_mac1, 0x5a, sizeof(wrong_mac1));
	wireguard_xaead_encrypt(forged.enc_cookie, cookie, sizeof(cookie), wrong_mac1, sizeof(wrong_mac1), forged.nonce, label_cookie_key);
	deliver(&device_side, (const uint8_t *)&forged, sizeof(forged), &OTHER_ADDR, OTHER_PORT);
	CHECK(peer->handshake_mac1_valid);
	CHECK(device_endpoint_is(&SERVER_ADDR, SERVER_PORT));

	/* The mac1 from the wire: the cookie is accepted (so the next check is
	 * not vacuous) and the endpoint still does not move */
	wireguard_xaead_encrypt(forged.enc_cookie, cookie, sizeof(cookie), seen.mac1, sizeof(seen.mac1), forged.nonce, label_cookie_key);
	deliver(&device_side, (const uint8_t *)&forged, sizeof(forged), &OTHER_ADDR, OTHER_PORT);
	CHECK(!peer->handshake_mac1_valid);
	CHECK(device_endpoint_is(&SERVER_ADDR, SERVER_PORT));
}

static void establish(void) {
	u8_t index;

	wireguardif_disable_socket_bind();
	side_up(&device_side, DEVICE_PORT);
	side_up(&server_side, SERVER_PORT);
	server_index_on_device = add_peer(&device_side, &server_side, 2, &SERVER_ADDR, SERVER_PORT);
	index = add_peer(&server_side, &device_side, 1, NULL, 0);   /* learns the endpoint from the handshake */
	(void)index;

	/* Device -> server: initiation */
	REQUIRE(wireguardif_connect(&device_side.netif, server_index_on_device) == ERR_OK);
	REQUIRE(device_side.sent == 1 && device_side.wire[0] == MESSAGE_HANDSHAKE_INITIATION);
	REQUIRE(ip_addr_cmp(&device_side.wire_ip, &SERVER_ADDR) && device_side.wire_port == SERVER_PORT);

	test_cookie_reply_does_not_roam();

	/* Server -> device: response */
	deliver(&server_side, device_side.wire, device_side.wire_len, &DEVICE_ADDR, DEVICE_PORT);
	REQUIRE(server_side.sent == 1 && server_side.wire[0] == MESSAGE_HANDSHAKE_RESPONSE);
	REQUIRE(ip_addr_cmp(&server_side.wire_ip, &DEVICE_ADDR) && server_side.wire_port == DEVICE_PORT);
	deliver(&device_side, server_side.wire, server_side.wire_len, &SERVER_ADDR, SERVER_PORT);

	/* Device -> server: the keep-alive that confirms the session */
	REQUIRE(device_side.sent == 2 && device_side.wire[0] == MESSAGE_TRANSPORT_DATA);
	deliver(&server_side, device_side.wire, device_side.wire_len, &DEVICE_ADDR, DEVICE_PORT);

	REQUIRE(wireguardif_peer_is_up(&device_side.netif, server_index_on_device, NULL, NULL) == ERR_OK);
	REQUIRE(device_endpoint_is(&SERVER_ADDR, SERVER_PORT));
}

static void test_replayed_data_does_not_roam(void) {
	uint8_t packet[sizeof(server_side.wire)];
	size_t len;
	struct wireguard_peer *peer = server_on_device();
	struct wireguard_peer before;

	server_sends_data();
	len = server_side.wire_len;
	memcpy(packet, server_side.wire, len);

	/* The original, from the server */
	clock_ms += 1000;
	device_side.delivered = 0;
	deliver(&device_side, packet, len, &SERVER_ADDR, SERVER_PORT);
	CHECK(device_side.delivered == 1);
	CHECK(peer->last_rx == clock_ms);
	CHECK(device_endpoint_is(&SERVER_ADDR, SERVER_PORT));

	/* The same bytes again, a minute later, from somewhere else */
	clock_ms += 60000;
	before = *peer;
	deliver(&device_side, packet, len, &OTHER_ADDR, OTHER_PORT);
	CHECK(device_side.delivered == 1);                      /* the replay window holds */
	CHECK(device_endpoint_is(&SERVER_ADDR, SERVER_PORT));   /* GHSA-jxrh-hg4w-g4rm */
	CHECK(peer->last_rx != clock_ms);
	CHECK(memcmp(&before, peer, sizeof(before)) == 0);      /* nothing at all changed */

	/* ... and from the right address too */
	deliver(&device_side, packet, len, &SERVER_ADDR, SERVER_PORT);
	CHECK(device_side.delivered == 1);
	CHECK(memcmp(&before, peer, sizeof(before)) == 0);
}

static void test_fresh_packet_still_roams(void) {
	uint8_t packet[sizeof(server_side.wire)];
	size_t len;

	/* The server moves: a packet the device has not seen, from a new address */
	server_sends_data();
	len = server_side.wire_len;
	memcpy(packet, server_side.wire, len);
	device_side.delivered = 0;
	deliver(&device_side, packet, len, &ROAMED_ADDR, ROAMED_PORT);
	CHECK(device_side.delivered == 1);
	CHECK(device_endpoint_is(&ROAMED_ADDR, ROAMED_PORT));

	/* Re-sending that packet from a third address does not move it again */
	deliver(&device_side, packet, len, &OTHER_ADDR, OTHER_PORT);
	CHECK(device_side.delivered == 1);
	CHECK(device_endpoint_is(&ROAMED_ADDR, ROAMED_PORT));

	/* The server moves back */
	server_sends_data();
	deliver(&device_side, server_side.wire, server_side.wire_len, &SERVER_ADDR, SERVER_PORT);
	CHECK(device_side.delivered == 2);
	CHECK(device_endpoint_is(&SERVER_ADDR, SERVER_PORT));
}

static void test_replayed_keepalive_changes_nothing(void) {
	uint8_t packet[sizeof(server_side.wire)];
	size_t len;
	unsigned sent_before = server_side.sent;
	struct wireguard_peer *peer = server_on_device();
	struct wireguard_peer before;

	/* Let the server's keep-alive timer fire */
	clock_ms += 26000;
	wireguardif_periodic(&server_side.netif);
	REQUIRE(server_side.sent == sent_before + 1);
	len = server_side.wire_len;
	REQUIRE(len == sizeof(struct message_transport_data) + WIREGUARD_AUTHTAG_LEN);   /* empty payload */
	memcpy(packet, server_side.wire, len);

	device_side.delivered = 0;
	deliver(&device_side, packet, len, &SERVER_ADDR, SERVER_PORT);
	CHECK(device_side.delivered == 0);          /* a keep-alive carries no IP packet */
	CHECK(peer->last_rx == clock_ms);

	clock_ms += 1000;
	before = *peer;
	deliver(&device_side, packet, len, &OTHER_ADDR, OTHER_PORT);
	CHECK(memcmp(&before, peer, sizeof(before)) == 0);
	CHECK(device_endpoint_is(&SERVER_ADDR, SERVER_PORT));
}

static void test_unauthenticated_packet_changes_nothing(void) {
	uint8_t packet[sizeof(server_side.wire)];
	uint8_t forged[sizeof(server_side.wire)];
	size_t len;
	struct message_transport_data *hdr = (struct message_transport_data *)forged;
	struct wireguard_peer *peer = server_on_device();
	struct wireguard_peer before;

	server_sends_data();
	len = server_side.wire_len;
	memcpy(packet, server_side.wire, len);

	/* Right receiver index, a counter far ahead, a broken ciphertext */
	memcpy(forged, packet, len);
	U64TO8_LITTLE(hdr->counter, U8TO64_LITTLE(hdr->counter) + 1000);
	forged[len - 1] ^= 0x01;

	clock_ms += 1000;
	before = *peer;
	device_side.delivered = 0;
	deliver(&device_side, forged, len, &OTHER_ADDR, OTHER_PORT);
	CHECK(device_side.delivered == 0);
	CHECK(memcmp(&before, peer, sizeof(before)) == 0);   /* the replay window did not move either */

	/* The authentic packet, with its lower counter, is still accepted */
	deliver(&device_side, packet, len, &SERVER_ADDR, SERVER_PORT);
	CHECK(device_side.delivered == 1);
	CHECK(device_endpoint_is(&SERVER_ADDR, SERVER_PORT));
}

int main(void) {
	IP_ADDR4(&DEVICE_ADDR, 192, 168, 1, 10);
	IP_ADDR4(&SERVER_ADDR, 203, 0, 113, 5);
	IP_ADDR4(&OTHER_ADDR, 192, 168, 1, 66);
	IP_ADDR4(&ROAMED_ADDR, 198, 51, 100, 7);

	establish();
	test_replayed_data_does_not_roam();
	test_fresh_packet_still_roams();
	test_replayed_keepalive_changes_nothing();
	test_unauthenticated_packet_changes_nothing();

	wireguardif_shutdown(&device_side.netif);
	wireguardif_free(&device_side.netif);
	wireguardif_shutdown(&server_side.netif);
	wireguardif_free(&server_side.netif);
	CHECK(live_pbufs == 0);
	CHECK(live_blocks == 0);

	if (failures) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	printf("wireguard roaming tests passed\n");
	return 0;
}
