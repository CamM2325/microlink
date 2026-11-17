/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Daniel Hope <daniel.hope@smartalock.com>
 */

#include "wireguardif.h"
#include "wireguard-filter.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdlib.h>

#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/ip6.h"
#include "lwip/udp.h"
#include "lwip/mem.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/tcpip.h"
#include "arch/sys_arch.h" /* sys_thread_tcpip() */

#include "wireguard.h"
#include "crypto.h"
#include "lwip_compat.h"

#include <stdbool.h>

/*
 * Locking. Packets are sent from tcpip_thread (netif output) and from the
 * wg_mgr task (keepalives, handshakes), received on wg_mgr (or on tcpip_thread
 * with CONFIG_ML_ZERO_COPY_WG), and peers are added and removed on wg_mgr.
 *
 * s_wg_tx_lock (state lock) covers a peer's keypairs (next/curr/prev), its
 * endpoint (ip/port, connect_ip/connect_port), its valid flag and the
 * handshake-control fields (send_handshake, last_initiation_tx,
 * handshake_attempts, active). Every
 * keypair mutation (add_new_keypair via wireguard_start_session,
 * keypair_update, keypair_destroy, peer init and the wipe on remove) takes it,
 * and so does the TX path from keypair selection to reserving the nonce.
 * Without it, a send preempting add_new_keypair() could read the new key with
 * the old counter, and a (key, nonce) pair would later be used twice.
 * Sections are short: no X25519, no AEAD, no lwIP call.
 *
 * s_wg_hs_lock covers the handshake state (peer->handshake, cookie, mac1,
 * greatest timestamp). It is held across the X25519 operations of a
 * handshake, so the TX path never takes it. Order: hs, then tx.
 *
 * Neither lock is ever held across wireguardif_dest_output() or any other
 * lwIP call: wg_udp_sendto_any_ctx() makes wg_mgr wait for tcpip_thread,
 * which may itself be waiting for one of these locks.
 */
static SemaphoreHandle_t s_wg_tx_lock;
static StaticSemaphore_t s_wg_tx_lock_buf;
static SemaphoreHandle_t s_wg_hs_lock;
static StaticSemaphore_t s_wg_hs_lock_buf;

static inline void wg_state_lock(void) { xSemaphoreTake(s_wg_tx_lock, portMAX_DELAY); }
static inline void wg_state_unlock(void) { xSemaphoreGive(s_wg_tx_lock); }
static inline void wg_hs_lock(void) { xSemaphoreTake(s_wg_hs_lock, portMAX_DELAY); }
static inline void wg_hs_unlock(void) { xSemaphoreGive(s_wg_hs_lock); }

/* Where a packet for a peer goes, copied under the state lock so a
 * concurrent remove or endpoint change can't hand the output path a torn
 * address or a half-wiped public key. */
struct wg_peer_dest {
	ip_addr_t ip;
	u16_t port;
	uint8_t public_key[WIREGUARD_PUBLIC_KEY_LEN];
};

#include "esp_log.h"

static const char *WG_TAG = "wg";

// Per-packet / per-call trace. ESP_LOGV, so it is compiled out unless the
// component is built at Verbose (CONFIG_ML_LOG_LEVEL_VERBOSE), and even then
// only printed after esp_log_level_set("wg", ESP_LOG_VERBOSE).
#define WG_DEBUG(...) ESP_LOGV(WG_TAG, __VA_ARGS__)

#define WIREGUARDIF_TIMER_MSECS 400

// Forward declaration for timer cancellation in wireguardif_shutdown
static void wireguardif_tmr(void *arg);

// Flag to disable internal UDP socket binding (for magicsock mode)
static bool g_disable_socket_bind = false;

void wireguardif_disable_socket_bind(void) {
	g_disable_socket_bind = true;
}

// netif_set_link_up()/netif_set_link_down() are core lwIP netif state and
// must only run on tcpip_thread (confirmed on real hardware via
// CONFIG_LWIP_CHECK_THREAD_SAFETY, which asserts immediately otherwise).
// The callers run on whatever task calls wireguardif_network_rx() or
// wireguardif_periodic(): normally the ml_wg_mgr task, but with
// CONFIG_ML_ZERO_COPY_WG the receive path runs on tcpip_thread itself.
//  - On tcpip_thread (or holding the core lock): set the flag directly.
//    Posting to our own mailbox with the blocking tcpip_callback() would
//    deadlock as soon as the mailbox is full under RX load.
//  - Elsewhere: tcpip_try_callback(), fire-and-forget and non-blocking.
//    Nothing here depends on the flag having changed before returning, and
//    a post dropped on a full mailbox is retried: link-up is re-checked on
//    every data packet, link-down on every periodic tick.
static void netif_set_link_up_in_tcpip(void *arg) {
	netif_set_link_up((struct netif *)arg);
}
static void netif_set_link_down_in_tcpip(void *arg) {
	netif_set_link_down((struct netif *)arg);
}
static void wireguardif_set_link(struct netif *netif, bool up) {
	if (sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
		if (up) {
			netif_set_link_up(netif);
		} else {
			netif_set_link_down(netif);
		}
		return;
	}
	if (tcpip_try_callback(up ? netif_set_link_up_in_tcpip : netif_set_link_down_in_tcpip, netif) != ERR_OK) {
		WG_DEBUG("[WG] link %s post dropped (tcpip mailbox full), will retry", up ? "up" : "down");
	}
}

static void wireguardif_mark_link_up(struct netif *netif) {
	// One call site is per-data-packet (wireguard_process_data_message()'s
	// defensive "make sure link is reported as up"), not just per-handshake -
	// skip the dispatch entirely once the flag is already set, so the common
	// case (link already up) costs one flag read, not a callback queued on
	// every packet. Reading netif->flags without the core lock is fine here:
	// it's a single bit, so a stale read costs at most one redundant (still
	// correct) dispatch, never a wrong result.
	if (netif->flags & NETIF_FLAG_LINK_UP) {
		return;
	}
	wireguardif_set_link(netif, true);
}

// Both call sites (wireguardif_tmr() and wireguardif_periodic(), the periodic
// per-peer keepalive/rekey/timeout sweep) run once per tick, not once per
// packet, but still worth skipping the dispatch once the flag is already
// clear (the common steady-state case, either "link up" or "link already
// reported down").
static void wireguardif_mark_link_down(struct netif *netif) {
	if (!(netif->flags & NETIF_FLAG_LINK_UP)) {
		return;
	}
	wireguardif_set_link(netif, false);
}


// The underlay is IPv4-only for now: every output path reads the destination
// with ip4_addr_get_u32(ip_2_ip4(...)), so an IPv6 endpoint would become a
// garbage IPv4 destination. Refuse IPv6 endpoints until that is implemented
// (all current callers only ever pass IPv4).
static bool wg_endpoint_usable(const ip_addr_t *addr) {
	return IP_IS_V4(addr) && wg_endpoint_is_valid_underlay(addr);
}

// Caller holds the state lock.
static void update_peer_addr(struct wireguard_peer *peer, const ip_addr_t *addr, u16_t port) {
	// Don't overwrite a valid endpoint with 0.0.0.0 (DERP-injected packets have no real source)
	// This bug was causing DERP routing to break after receiving the first packet
	if (ip_addr_isany(addr)) {
		WG_DEBUG("[WG] update_peer_addr: skipping DERP (0.0.0.0)");
		return;  // Skip updating endpoint for DERP packets
	}
	if (!wg_endpoint_usable(addr)) {
		WG_DEBUG("[WG] update_peer_addr: refusing non-underlay endpoint %s", ipaddr_ntoa(addr));
		return;
	}
	WG_DEBUG("[WG] update_peer_addr: %s:%u", ipaddr_ntoa(addr), port);
	peer->ip = *addr;
	peer->port = port;
}

static void update_peer_addr_locked(struct wireguard_peer *peer, const ip_addr_t *addr, u16_t port) {
	wg_state_lock();
	update_peer_addr(peer, addr, port);
	wg_state_unlock();
}

// Caller holds the state lock.
static void wg_peer_dest_get(const struct wireguard_peer *peer, struct wg_peer_dest *dest) {
	dest->ip = peer->ip;
	dest->port = peer->port;
	memcpy(dest->public_key, peer->public_key, WIREGUARD_PUBLIC_KEY_LEN);
}

static void wg_peer_dest_snapshot(struct wireguard_peer *peer, struct wg_peer_dest *dest) {
	wg_state_lock();
	wg_peer_dest_get(peer, dest);
	wg_state_unlock();
}

static bool wireguardif_can_send_initiation(struct wireguard_peer *peer) {
	return ((peer->last_initiation_tx == 0) || (wireguard_expired(peer->last_initiation_tx, REKEY_TIMEOUT)));
}

// Sends q to dest (direct UDP, or DERP when dest has no address). Must be
// called without either lock held.
static err_t wireguardif_dest_output(struct netif *netif, struct pbuf *q, const struct wg_peer_dest *dest) {
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	// Each callback pointer is read once: wireguardif_detach_outputs() may
	// clear them from another task (the callbacks tolerate a NULL ctx).
	wireguard_derp_output_fn derp_fn = __atomic_load_n(&device->derp_output_fn, __ATOMIC_ACQUIRE);
	wireguard_udp_output_pbuf_fn pbuf_fn = __atomic_load_n(&device->udp_output_pbuf_fn, __ATOMIC_ACQUIRE);
	wireguard_udp_output_fn udp_fn = __atomic_load_n(&device->udp_output_fn, __ATOMIC_ACQUIRE);

	WG_DEBUG("[WG_OUT] peer_output: endpoint=%s:%u, tot_len=%u",
	       ip_addr_isany(&dest->ip) ? "0.0.0.0" : ipaddr_ntoa(&dest->ip), dest->port, (unsigned)q->tot_len);


	// Check if peer has a direct endpoint (non-zero IP and port)
	// If not, use DERP relay callback if available.
	// force_derp_output: cellular mode — always route through DERP.
	if (ip_addr_isany(&dest->ip) || dest->port == 0 || device->force_derp_output) {
		WG_DEBUG("[WG_OUT] No direct endpoint or force_derp, checking DERP");

		if (derp_fn) {
			// Linearize pbuf chain into contiguous buffer for DERP callback
			uint8_t *data = (uint8_t *)mem_malloc(q->tot_len);
			if (data) {
				pbuf_copy_partial(q, data, q->tot_len, 0);
				err_t result = derp_fn(dest->public_key, data, q->tot_len, __atomic_load_n(&device->derp_output_ctx, __ATOMIC_ACQUIRE));
				mem_free(data);
				return result;
			}
			WG_DEBUG("[WG_OUT] DERP mem_malloc failed!");
		
			return ERR_MEM;
		}
		// No DERP callback and no direct endpoint - can't send
		WG_DEBUG("[WG_OUT] No DERP callback, returning ERR_RTE");
	
		return ERR_RTE;
	}

	// Zero-copy magicsock output: hand the encrypted pbuf over untouched.
	if (pbuf_fn) {
		uint32_t dest_ip = ip4_addr_get_u32(ip_2_ip4(&dest->ip));
		return pbuf_fn(dest_ip, dest->port, q, __atomic_load_n(&device->udp_output_pbuf_ctx, __ATOMIC_ACQUIRE));
	}

	// In magicsock mode, use external UDP output callback
	if (udp_fn) {
		WG_DEBUG("[WG_OUT] Using magicsock callback");
	
		// Linearize pbuf chain and send via callback
		uint8_t *data = (uint8_t *)mem_malloc(q->tot_len);
		if (data) {
			WG_DEBUG("[WG_OUT] mem_malloc OK, copying pbuf");
		
			pbuf_copy_partial(q, data, q->tot_len, 0);
			// Convert lwIP IP address to network byte order uint32_t
			uint32_t dest_ip = ip4_addr_get_u32(ip_2_ip4(&dest->ip));
			WG_DEBUG("[WG_OUT] Calling udp_output_fn, dest_ip=0x%08lx port=%u len=%u",
			       (unsigned long)dest_ip, dest->port, (unsigned)q->tot_len);
		
			err_t result = udp_fn(dest_ip, dest->port, data, q->tot_len, __atomic_load_n(&device->udp_output_ctx, __ATOMIC_ACQUIRE));
			WG_DEBUG("[WG_OUT] udp_output_fn returned %d", result);
		
			mem_free(data);
			return result;
		}
		WG_DEBUG("[WG_OUT] mem_malloc FAILED for magicsock!");
	
		return ERR_MEM;
	}

	WG_DEBUG("[WG_OUT] Using direct udp_sendto");

	// Send to last known port, not the connect port
	//TODO: Support DSCP and ECN - lwip requires this set on PCB globally, not per packet
	if (!device->udp_pcb) {
		// Magicsock mode with the output callbacks detached
		return ERR_RTE;
	}
	return udp_sendto(device->udp_pcb, q, &dest->ip, dest->port);
}

static err_t wireguardif_device_output(struct wireguard_device *device, struct pbuf *q, const ip_addr_t *ipaddr, u16_t port) {
	wireguard_udp_output_pbuf_fn pbuf_fn = __atomic_load_n(&device->udp_output_pbuf_fn, __ATOMIC_ACQUIRE);
	wireguard_udp_output_fn udp_fn = __atomic_load_n(&device->udp_output_fn, __ATOMIC_ACQUIRE);
	if (pbuf_fn) {
		uint32_t dest_ip = ip4_addr_get_u32(ip_2_ip4(ipaddr));
		return pbuf_fn(dest_ip, port, q, __atomic_load_n(&device->udp_output_pbuf_ctx, __ATOMIC_ACQUIRE));
	}

	// In magicsock mode, use external UDP output callback
	if (udp_fn) {
		uint8_t *data = (uint8_t *)mem_malloc(q->tot_len);
		if (data) {
			pbuf_copy_partial(q, data, q->tot_len, 0);
			uint32_t dest_ip = ip4_addr_get_u32(ip_2_ip4(ipaddr));
			err_t result = udp_fn(dest_ip, port, data, q->tot_len, __atomic_load_n(&device->udp_output_ctx, __ATOMIC_ACQUIRE));
			mem_free(data);
			return result;
		}
		return ERR_MEM;
	}
	if (!device->udp_pcb) {
		return ERR_RTE;
	}
	return udp_sendto(device->udp_pcb, q, ipaddr, port);
}

static err_t wireguardif_output_to_peer(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr, struct wireguard_peer *peer) {
	// The LWIP IP layer wants to send an IP packet out over the interface - we need to encrypt and send it to the peer
	struct message_transport_data *hdr;
	struct pbuf *pbuf;
	err_t result;
	size_t unpadded_len;
	size_t padded_len;
	size_t header_len = 16;
	uint8_t *dst;
	struct wireguard_keypair *keypair;
	struct wg_peer_dest dest;
	uint8_t sending_key[WIREGUARD_SESSION_KEY_LEN];
	uint64_t counter;
	uint32_t receiver;

	// Unlocked hint only (re-checked under the lock): don't allocate a pbuf
	// for a peer that has no keys at all.
	if (!peer->curr_keypair.valid && !peer->prev_keypair.valid) {
		return ERR_CONN;
	}

	// Calculate the outgoing packet size - round up to next 16 bytes, add 16 bytes for header
	if (q) {
		// This is actual transport data
		unpadded_len = q->tot_len;
	} else {
		// This is a keep-alive
		unpadded_len = 0;
	}
	padded_len = (unpadded_len + 15) & 0xFFFFFFF0; // Round up to next 16 byte boundary

	// The buffer needs to be allocated from "transport" pool to leave room for LwIP generated IP headers
	// The IP packet consists of 16 byte header (struct message_transport_data), data padded upto 16 byte boundary + encrypted auth tag (16 bytes)
	pbuf = pbuf_alloc(PBUF_TRANSPORT, header_len + padded_len + WIREGUARD_AUTHTAG_LEN, PBUF_RAM);
	if (!pbuf) {
		return ERR_MEM;
	}
	// Note: allocating pbuf from RAM above guarantees that the pbuf is in one section and not chained
	// - i.e payload points to the contiguous memory region
	memset(pbuf->payload, 0, pbuf->tot_len);
	hdr = (struct message_transport_data *)pbuf->payload;
	hdr->type = MESSAGE_TRANSPORT_DATA;

	// Copy the encrypted (padded) data to the output packet - chacha20poly1305_encrypt() can encrypt data in-place which avoids call to mem_malloc
	dst = &hdr->enc_packet[0];
	if ((padded_len > 0) && q) {
		// Note: before copying make sure we have inserted the IP header checksum
		// The IP header checksum (and other checksums in the IP packet - e.g. ICMP) need to be calculated by LWIP before calling
		// The Wireguard interface always needs checksums to be generated in software but the base netif may have some checksums generated by hardware

		// Copy pbuf to memory - handles case where pbuf is chained
		pbuf_copy_partial(q, dst, unpadded_len, 0);
	}

	// SECURITY: the send counter is the AEAD nonce. Keypair selection, the
	// validity checks and the counter reservation happen in one critical
	// section with every keypair mutation (see the locking notes at the top),
	// so the key and the counter always belong to the same keypair and no
	// counter value is handed out twice for a key. The key is copied out and
	// the AEAD runs after unlocking: the (key, nonce) pair is already unique.
	wg_state_lock();
	if (!peer->valid) {
		// Removed after the unlocked route lookup picked it
		wg_state_unlock();
		pbuf_free(pbuf);
		return ERR_CONN;
	}
	keypair = wg_peer_tx_keypair(peer);
	if (!keypair) {
		// No valid keys!
		result = ERR_CONN;
	} else if (wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) ||
			(keypair->sending_counter >= REJECT_AFTER_MESSAGES)) {
		// key has expired...
		keypair_destroy(keypair);
		result = ERR_CONN;
	} else {
		memcpy(sending_key, keypair->sending_key, sizeof(sending_key));
		counter = keypair->sending_counter++;
		receiver = keypair->remote_index;
		// Check to see if we should rekey
		if (keypair->sending_counter >= REKEY_AFTER_MESSAGES) {
			peer->send_handshake = true;
		} else if (keypair->initiator && wireguard_expired(keypair->keypair_millis, REKEY_AFTER_TIME)) {
			peer->send_handshake = true;
		}
		wg_peer_dest_get(peer, &dest);
		result = ERR_OK;
	}
	wg_state_unlock();

	if (result != ERR_OK) {
		pbuf_free(pbuf);
		return result;
	}

	hdr->receiver = receiver;
	U64TO8_LITTLE(hdr->counter, counter);
	wireguard_aead_encrypt(dst, dst, padded_len, NULL, 0, counter, sending_key);
	crypto_zero(sending_key, sizeof(sending_key));

	WG_DEBUG("[WG_TX] Sending encrypted DATA packet: %u bytes, remote_idx=%lu",
	       (unsigned)pbuf->tot_len, (unsigned long)receiver);

	result = wireguardif_dest_output(netif, pbuf, &dest);
	WG_DEBUG("[WG_TX] peer_output result=%d", result);

	if (result == ERR_OK) {
		uint32_t now = wireguard_sys_now();
		wg_state_lock();
		if (peer->valid) {
			peer->last_tx = now;
		}
		wg_state_unlock();
	}

	pbuf_free(pbuf);
	return result;
}

// This is used as the output function for the Wireguard netif
// The ipaddr here is the one inside the VPN which we use to lookup the correct peer/endpoint
static err_t wireguardif_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr) {
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	if (device->tx_note_fn && q) {
		uint8_t hdr[28];
		u16_t n = pbuf_copy_partial(q, hdr, sizeof(hdr), 0);
		device->tx_note_fn(device->filter_ctx, hdr, n);
	}
	// Send to peer that matches dest IP
	// Convert ip4_addr_t to ip_addr_t for lookup
	ip_addr_t addr;
	ip_addr_copy_from_ip4(addr, *ipaddr);

	WG_DEBUG("[WG_OUTPUT] Looking up peer for dest %s", ipaddr_ntoa(&addr));


	struct wireguard_peer *peer = wg_peer_lookup_by_allowed_ip(device, &addr);
	if (peer) {
		WG_DEBUG("[WG_OUTPUT] Found peer, peer_index=%d, valid=%d",
		       (int)(peer - device->peers), peer->valid);
	
		return wireguardif_output_to_peer(netif, q, ipaddr, peer);
	} else {
		WG_DEBUG("[WG_OUTPUT] NO PEER FOUND for %s! Dumping all peers:", ipaddr_ntoa(&addr));
		for (int i = 0; i < WIREGUARD_MAX_PEERS; i++) {
			struct wireguard_peer *p = &device->peers[i];
			if (p->valid) {
				WG_DEBUG("  peer[%d]: valid=%d, curr_keypair.valid=%d, last_rx=%lu",
				       i, p->valid, p->curr_keypair.valid, (unsigned long)p->curr_keypair.last_rx);
				for (int j = 0; j < WIREGUARD_MAX_SRC_IPS; j++) {
					if (p->allowed_source_ips[j].valid) {
						WG_DEBUG("    allowed[%d]: %s/%s", j,
						       ipaddr_ntoa(&p->allowed_source_ips[j].ip),
						       ipaddr_ntoa(&p->allowed_source_ips[j].mask));
					}
				}
			}
		}
	
		return ERR_RTE;
	}
}

#if LWIP_IPV6
// IPv6 into the tunnel: the peer is chosen by its allowed IPs, as for IPv4
// (each peer's tailnet IPv6 /128 is added with wireguardif_add_allowed_ip).
static err_t wireguardif_output_ip6(struct netif *netif, struct pbuf *q, const ip6_addr_t *ip6addr) {
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	ip_addr_t addr;
	ip_addr_copy_from_ip6(addr, *ip6addr);
	struct wireguard_peer *peer = wg_peer_lookup_by_allowed_ip(device, &addr);
	if (!peer) {
		return ERR_RTE;
	}
	return wireguardif_output_to_peer(netif, q, NULL, peer);
}
#endif /* LWIP_IPV6 */

static void wireguardif_send_keepalive(struct wireguard_device *device, struct wireguard_peer *peer) {
	// Send a NULL packet as a keep-alive
	wireguardif_output_to_peer(device->netif, NULL, NULL, peer);
}

static void wireguardif_process_response_message(struct wireguard_device *device, struct message_handshake_response *response, const ip_addr_t *addr, u16_t port) {
	WG_DEBUG("[WG] Processing handshake response from %s:%u",
		ip_addr_isany(addr) ? "DERP" : ipaddr_ntoa(addr), port);

	wg_hs_lock();
	struct wireguard_peer *peer = peer_lookup_by_handshake(device, response->receiver);
	if (!peer) {
		wg_hs_unlock();
		ESP_LOGD(WG_TAG, "Handshake response dropped: no pending handshake for receiver_idx=%lu", (unsigned long)response->receiver);
		return;
	}
	if (!wireguard_process_handshake_response(device, peer, response)) {
		wg_hs_unlock();
		// Packet bad
		ESP_LOGW(WG_TAG, "Handshake response rejected (crypto check failed)");
		return;
	}
	wg_state_lock();
	// Update the peer location
	update_peer_addr(peer, addr, port);
	// Session is up - reset the give-up counter for the next time we need it.
	peer->handshake_attempts = 0;
	wireguard_start_session(peer, true);
	wg_state_unlock();
	wg_hs_unlock();

	// Packet is good — identify the peer
	uint8_t wg_idx = wireguard_peer_index(device, peer);
	ESP_LOGI(WG_TAG, "Handshake complete (initiator): wg_idx=%u key=%02x%02x%02x%02x via %s:%u",
	       wg_idx,
	       peer->public_key[0], peer->public_key[1],
	       peer->public_key[2], peer->public_key[3],
	       ip_addr_isany(addr) ? "DERP" : ipaddr_ntoa(addr), port);
	wireguardif_send_keepalive(device, peer);

	// Set the IF-UP flag on netif
	wireguardif_mark_link_up(device->netif);
	ESP_LOGD(WG_TAG, "Session established wg_idx=%u", wg_idx);
}

static bool peer_add_ip(struct wireguard_peer *peer, ip_addr_t ip, ip_addr_t mask);

err_t wireguardif_add_allowed_ip(struct netif *netif, u8_t peer_index, const ip_addr_t *ip, const ip_addr_t *mask) {
	struct wireguard_device *device = netif ? (struct wireguard_device *)netif->state : NULL;
	if (!device || peer_index >= WIREGUARD_MAX_PEERS || !ip || !mask) {
		return ERR_ARG;
	}
	struct wireguard_peer *peer = &device->peers[peer_index];
	// Lookups on tcpip_thread scan the slots without the lock; peer_add_ip
	// writes address and mask before it marks the slot valid.
	wg_state_lock();
	bool ok = peer->valid && peer_add_ip(peer, *ip, *mask);
	wg_state_unlock();
	return ok ? ERR_OK : ERR_MEM;
}

static bool peer_add_ip(struct wireguard_peer *peer, ip_addr_t ip, ip_addr_t mask) {
	bool result = false;
	struct wireguard_allowed_ip *allowed;
	int x;
	// Look for existing match first
	for (x=0; x < WIREGUARD_MAX_SRC_IPS; x++) {
		allowed = &peer->allowed_source_ips[x];
		if ((allowed->valid) && ip_addr_cmp(&allowed->ip, &ip) && ip_addr_cmp(&allowed->mask, &mask)) {
			result = true;
			break;
		}
	}
	if (!result) {
		// Look for a free slot
		for (x=0; x < WIREGUARD_MAX_SRC_IPS; x++) {
			allowed = &peer->allowed_source_ips[x];
			if (!allowed->valid) {
				allowed->ip = ip;
				allowed->mask = mask;
				__atomic_thread_fence(__ATOMIC_RELEASE);
				allowed->valid = true;
				result = true;
				break;
			}
		}
	}
	return result;
}

static void wireguardif_process_data_message(struct wireguard_device *device, struct wireguard_peer *peer, struct message_transport_data *data_hdr, size_t data_len, const ip_addr_t *addr, u16_t port) {
	struct wireguard_keypair *keypair;
	uint64_t nonce;
	uint8_t *src;
	size_t src_len;
	struct pbuf *pbuf;
	bool dest_ok = false;
	uint32_t now;
	uint16_t header_len = 0xFFFF;
	uint32_t idx = data_hdr->receiver;

	keypair = get_peer_keypair_for_idx(peer, idx);

	if (keypair) {
		if ((keypair->receiving_valid) && !wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME)) {

			nonce = U8TO64_LITTLE(data_hdr->counter);
			src = &data_hdr->enc_packet[0];
			src_len = data_len;

			// Reject-After-Messages applies to the RECEIVED counter. The counter is
			// not authenticated yet, so only drop this packet - never destroy the
			// keypair on the strength of it.
			pbuf = NULL;
			if (nonce < REJECT_AFTER_MESSAGES) {
				// We don't know the unpadded size until we have decrypted the packet and validated/inspected the IP header
				pbuf = pbuf_alloc(PBUF_TRANSPORT, src_len - WIREGUARD_AUTHTAG_LEN, PBUF_RAM);
			}
			if (pbuf) {
				// Decrypt the packet
				memset(pbuf->payload, 0, pbuf->tot_len);
				bool decrypt_ok = wireguard_decrypt_packet(pbuf->payload, src, src_len, nonce, keypair);
				WG_DEBUG("[WG_DECRYPT] result=%d, src_len=%u, nonce=%lu",
				       decrypt_ok, (unsigned)src_len, (unsigned long)nonce);

				// SECURITY: the anti-replay check runs immediately after authentication
				// and BEFORE any peer/keypair state is touched - for every packet,
				// keep-alives included. Otherwise a captured packet re-sent from another
				// address moves the peer endpoint (endpoint hijack), refreshes last_rx,
				// rotates keypairs, or brings the link up.
				// The decrypt above ran without the state lock; the keypair may have
				// been rotated or destroyed meanwhile (keypair_update/destroy on
				// another task), so it is re-validated by its index before the replay
				// window or any other state is updated.
				bool fresh = false;
				u8_t ver = 0;
				if (decrypt_ok) {
					// 4a. Plaintext must be a well-formed IP packet, otherwise drop.
					// Parsed here (pure) so that 4b can run under the lock below.
					ip_addr_t src_ip;
					bool have_src = false;
					if (pbuf->tot_len > 0) {
						const struct ip_hdr *iphdr = (const struct ip_hdr *)pbuf->payload;
						ver = (pbuf->len >= 1) ? IPH_V(iphdr) : 0;
#if LWIP_IPV4
						if (ver == 4 && pbuf->len >= IP_HLEN) {
							ip_addr_copy_from_ip4(src_ip, iphdr->src);
							header_len = PP_NTOHS(IPH_LEN(iphdr));
							have_src = (header_len >= IP_HLEN);
						}
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
						if (ver == 6 && pbuf->len >= IP6_HLEN) {
							const struct ip6_hdr *ip6hdr = (const struct ip6_hdr *)pbuf->payload;
							ip_addr_copy_from_ip6_packed(src_ip, ip6hdr->src);
							header_len = (uint16_t)(IP6_HLEN + IP6H_PLEN(ip6hdr));
							have_src = true;
						}
#endif /* LWIP_IPV6 */
					}

					wg_state_lock();
					if (keypair->valid && (keypair->local_index == idx) && wireguard_check_replay(keypair, nonce)) {
						fresh = true;

						// 4b. The inner SOURCE address must route back to this same peer in
						// the cryptokey routing table (longest-prefix match over all peers).
						// Under the lock, so a concurrent remove + re-add of this slot can't
						// have the check run against the next occupant's allowed IPs.
						dest_ok = have_src && wg_peer_allowed_source(device, peer, &src_ip);

						// 3. Authentic and fresh: the outer source address may now update the
						// peer endpoint (roaming). DERP-delivered packets (0.0.0.0) are ignored.
						update_peer_addr(peer, addr, port);

						now = wireguard_sys_now();
						keypair->last_rx = now;
						peer->last_rx = now;

						// Check to see if we should rekey
						if (keypair->initiator && wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME - peer->keepalive_interval - REKEY_TIMEOUT)) {
							peer->send_handshake = true;
						}

						// Might need to shuffle next key --> current keypair. If 'keypair' was
						// next_keypair it has been copied to curr_keypair and its slot zeroed,
						// so it must not be used after this point.
						keypair_update(peer, keypair);
					}
					wg_state_unlock();
					keypair = NULL;
				}

				if (fresh) {
					// Make sure that link is reported as up
					wireguardif_mark_link_up(device->netif);

					if (pbuf->tot_len > 0) {
						if (!dest_ok) {
							WG_DEBUG("[WG_RX_IP] DROPPED: v%u inner source not routed to this peer (or malformed)", (unsigned)ver);
						} else if (header_len > pbuf->tot_len) {
							// IP header is corrupt or lied about packet size
							WG_DEBUG("[WG_RX_IP] DROPPED: header_len=%u > tot_len=%u",
							       (unsigned)header_len, (unsigned)pbuf->tot_len);
						} else if (device->rx_filter_fn &&
						           !device->rx_filter_fn(device->filter_ctx, (const uint8_t *)pbuf->payload, pbuf->tot_len)) {
							// Not allowed by the tailnet packet filter (ACLs)
							WG_DEBUG("[WG_RX_IP] DROPPED by packet filter");
						} else {
							// 5. Deliver via netif->input (= tcpip_input), never ip_input():
							// this runs on the wg_mgr task, and lwIP's IP/TCP input must run
							// on tcpip_thread (issue #17).
							WG_DEBUG("[WG_RX_IP] Passing %u bytes to IP layer", (unsigned)pbuf->tot_len);
							err_t input_err = device->netif->input(pbuf, device->netif);
							if (input_err == ERR_OK) {
								// pbuf ownership transferred to netif->input()
								pbuf = NULL;
							} else {
								WG_DEBUG("[WG_RX_IP] netif->input() failed: %d, dropping", input_err);
							}
						}
					} else {
						// This was a keep-alive packet
					}
				} else if (decrypt_ok) {
					// Authenticated but duplicate / replayed / too old (or the keypair
					// went away while decrypting): change nothing
					WG_DEBUG("[WG_RX] DROPPED: replayed or too old, nonce=%lu", (unsigned long)nonce);
				}

				if (pbuf) {
					pbuf_free(pbuf);
				}
			}

		} else {
			// After the current secure session is Reject-After-Time seconds old WireGuard will refuse
			// to send or receive any more transport data messages using it, until a new secure session
			// is created through the 1-RTT handshake. (Reject-After-Messages is checked above against
			// the received counter and only drops that packet.)
			wg_state_lock();
			if (keypair->valid && (keypair->local_index == idx)) {
				keypair_destroy(keypair);
			}
			wg_state_unlock();
		}

	} else {
		// Could not locate valid keypair for remote index
	}
}

// Wraps a handshake message in a pbuf for output. No lock may be held.
static struct pbuf *wireguardif_msg_pbuf(const void *msg, size_t len) {
	struct pbuf *pbuf = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
	if (pbuf && pbuf_take(pbuf, msg, len) != ERR_OK) {
		pbuf_free(pbuf);
		pbuf = NULL;
	}
	return pbuf;
}

// Caller holds the handshake lock (not the state lock). Builds the response
// and starts the responder session; the caller sends it after unlocking.
static bool wireguardif_build_handshake_response(struct wireguard_device *device, struct wireguard_peer *peer, struct message_handshake_response *packet) {
	if (!wireguard_create_handshake_response(device, peer, packet)) {
		return false;
	}
	wg_state_lock();
	wireguard_start_session(peer, false);
	wg_state_unlock();
	return true;
}

static size_t get_source_addr_port(const ip_addr_t *addr, u16_t port, uint8_t *buf, size_t buflen) {
	size_t result = 0;

#if LWIP_IPV4
	if (IP_IS_V4(addr) && (buflen >= 4)) {
		U32TO8_BIG(buf + result, PP_NTOHL(ip4_addr_get_u32(IP_ADDR_TO_IP4(addr))));
		result += 4;
	}
#endif
#if LWIP_IPV6
	if (IP_IS_V6(addr) && (buflen >= result + 16)) {
		const ip6_addr_t *ip6 = ip_2_ip6(addr);
		U16TO8_BIG(buf + result + 0, IP6_ADDR_BLOCK1(ip6));
		U16TO8_BIG(buf + result + 2, IP6_ADDR_BLOCK2(ip6));
		U16TO8_BIG(buf + result + 4, IP6_ADDR_BLOCK3(ip6));
		U16TO8_BIG(buf + result + 6, IP6_ADDR_BLOCK4(ip6));
		U16TO8_BIG(buf + result + 8, IP6_ADDR_BLOCK5(ip6));
		U16TO8_BIG(buf + result + 10, IP6_ADDR_BLOCK6(ip6));
		U16TO8_BIG(buf + result + 12, IP6_ADDR_BLOCK7(ip6));
		U16TO8_BIG(buf + result + 14, IP6_ADDR_BLOCK8(ip6));
		result += 16;
	}
#endif
	if (buflen >= result + 2) {
		U16TO8_BIG(buf + result, port);
		result += 2;
	}
	return result;
}

static void wireguardif_send_handshake_cookie(struct wireguard_device *device, const uint8_t *mac1, uint32_t index, const ip_addr_t *addr, u16_t port) {
	struct message_cookie_reply packet;
	struct pbuf *pbuf = NULL;
	err_t err = ERR_OK;
	uint8_t source_buf[18];
	size_t source_len = get_source_addr_port(addr, port, source_buf, sizeof(source_buf));

	wireguard_create_cookie_reply(device, &packet, mac1, index, source_buf, source_len);

	// Send this packet out!
	pbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct message_cookie_reply), PBUF_RAM);
	if (pbuf) {
		err = pbuf_take(pbuf, &packet, sizeof(struct message_cookie_reply));
		if (err == ERR_OK) {
			wireguardif_device_output(device, pbuf, addr, port);
		}
		pbuf_free(pbuf);
	}
}

static bool wireguardif_check_initiation_message(struct wireguard_device *device, struct message_handshake_initiation *msg, const ip_addr_t *addr, u16_t port) {
	bool result = false;
	uint8_t *data = (uint8_t *)msg;
	uint8_t source_buf[18];
	size_t source_len;
	// We received an initiation packet check it is valid

	if (wireguard_check_mac1(device, data, sizeof(struct message_handshake_initiation) - (2 * WIREGUARD_COOKIE_LEN), msg->mac1)) {
		// mac1 is valid!
		if (!wireguard_is_under_load()) {
			// If we aren't under load we only need mac1 to be correct
			result = true;
		} else {
			// If we are under load then check mac2
			source_len = get_source_addr_port(addr, port, source_buf, sizeof(source_buf));

			result = wireguard_check_mac2(device, data, sizeof(struct message_handshake_initiation) - (WIREGUARD_COOKIE_LEN), source_buf, source_len, msg->mac2);

			if (!result) {
				// mac2 is invalid (cookie may have expired) or not present
				// 5.3 Denial of Service Mitigation & Cookies
				// If the responder receives a message with a valid msg.mac1 yet with an invalid msg.mac2, and is under load, it may respond with a cookie reply message
				wireguardif_send_handshake_cookie(device, msg->mac1, msg->sender, addr, port);
			}
		}

	} else {
		// mac1 is invalid
	}
	return result;
}

static bool wireguardif_check_response_message(struct wireguard_device *device, struct message_handshake_response *msg, const ip_addr_t *addr, u16_t port) {
	bool result = false;
	uint8_t *data = (uint8_t *)msg;
	uint8_t source_buf[18];
	size_t source_len;
	// We received an initiation packet check it is valid

	if (wireguard_check_mac1(device, data, sizeof(struct message_handshake_response) - (2 * WIREGUARD_COOKIE_LEN), msg->mac1)) {
		// mac1 is valid!
		if (!wireguard_is_under_load()) {
			// If we aren't under load we only need mac1 to be correct
			result = true;
		} else {
			// If we are under load then check mac2
			source_len = get_source_addr_port(addr, port, source_buf, sizeof(source_buf));

			result = wireguard_check_mac2(device, data, sizeof(struct message_handshake_response) - (WIREGUARD_COOKIE_LEN), source_buf, source_len, msg->mac2);

			if (!result) {
				// mac2 is invalid (cookie may have expired) or not present
				// 5.3 Denial of Service Mitigation & Cookies
				// If the responder receives a message with a valid msg.mac1 yet with an invalid msg.mac2, and is under load, it may respond with a cookie reply message
				wireguardif_send_handshake_cookie(device, msg->mac1, msg->sender, addr, port);
			}
		}

	} else {
		// mac1 is invalid
	}
	return result;
}


void wireguardif_network_rx(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
	LWIP_ASSERT("wireguardif_network_rx: invalid arg", arg != NULL);
	LWIP_ASSERT("wireguardif_network_rx: invalid pbuf", p != NULL);
	// We have received a packet from the base_netif to our UDP port - process this as a possible Wireguard packet
	struct wireguard_device *device = (struct wireguard_device *)arg;
	struct wireguard_peer *peer;
	uint8_t *data = p->payload;
	size_t len = p->len; // This buf, not chained ones

	struct message_handshake_initiation *msg_initiation;
	struct message_handshake_response *msg_response;
	struct message_cookie_reply *msg_cookie;
	struct message_transport_data *msg_data;

	uint8_t type = wireguard_get_message_type(data, len);

	// Per-packet trace (WG_DEBUG = ESP_LOGV). It must stay compiled out by
	// default: printing here blocks the datapath on the UART for every packet.
	WG_DEBUG("[WG_RX] type=%d (%s) len=%u from %s:%u",
		type,
		type == 1 ? "INIT" : type == 2 ? "RESP" : type == 3 ? "COOKIE" : type == 4 ? "DATA" : "?",
		(unsigned)len,
		ip_addr_isany(addr) ? "DERP" : ipaddr_ntoa(addr), port);

	switch (type) {
		case MESSAGE_HANDSHAKE_INITIATION:
			msg_initiation = (struct message_handshake_initiation *)data;
			ESP_LOGD(WG_TAG, "Handshake initiation received, sender_idx=%lu",
				(unsigned long)msg_initiation->sender);

			// Check mac1 (and optionally mac2) are correct - note it may internally generate a cookie reply packet
			if (wireguardif_check_initiation_message(device, msg_initiation, addr, port)) {
				WG_DEBUG("Initiation MAC check passed");

				wg_hs_lock();
				peer = wireguard_process_initiation_message(device, msg_initiation);
				if (peer) {
					// Update the peer location
					update_peer_addr_locked(peer, addr, port);

					// Build the response and start the responder session
					struct message_handshake_response resp_msg;
					bool resp_ok = wireguardif_build_handshake_response(device, peer, &resp_msg);

					// If the initiation arrived via DERP (addr=0.0.0.0), answer via
					// DERP too: the ESP32 on cellular may not reach the peer's
					// direct endpoint.
					struct wg_peer_dest dest;
					wg_peer_dest_snapshot(peer, &dest);
					if (ip_addr_isany(addr)) {
						ip_addr_set_any(false, &dest.ip);
						dest.port = 0;
						ESP_LOGD(WG_TAG, "Sending response via DERP (initiation was relayed)");
					}
					wg_hs_unlock();

					ESP_LOGI(WG_TAG, "Handshake initiation accepted (responder): wg_idx=%u key=%02x%02x%02x%02x via %s:%u",
					       wireguard_peer_index(device, peer),
					       dest.public_key[0], dest.public_key[1],
					       dest.public_key[2], dest.public_key[3],
					       ip_addr_isany(addr) ? "DERP" : ipaddr_ntoa(addr), port);
					if (resp_ok) {
						struct pbuf *resp = wireguardif_msg_pbuf(&resp_msg, sizeof(resp_msg));
						if (resp) {
							wireguardif_dest_output(device->netif, resp, &dest);
							pbuf_free(resp);
						}
					}
				} else {
					wg_hs_unlock();
					ESP_LOGW(WG_TAG, "Handshake initiation rejected (unknown peer, bad keys or replayed timestamp)");
				}
			} else {
				ESP_LOGD(WG_TAG, "Handshake initiation dropped: MAC check failed");
			}
			break;

		case MESSAGE_HANDSHAKE_RESPONSE:
			msg_response = (struct message_handshake_response *)data;
			ESP_LOGD(WG_TAG, "Handshake response received, receiver_idx=%lu sender_idx=%lu",
				(unsigned long)msg_response->receiver, (unsigned long)msg_response->sender);

			// Check mac1 (and optionally mac2) are correct - note it may internally generate a cookie reply packet
			if (wireguardif_check_response_message(device, msg_response, addr, port)) {
				WG_DEBUG("Response MAC check passed");

				wireguardif_process_response_message(device, msg_response, addr, port);
			} else {
				ESP_LOGD(WG_TAG, "Handshake response dropped: MAC check failed");
			}
			break;

		case MESSAGE_COOKIE_REPLY:
			msg_cookie = (struct message_cookie_reply *)data;
			wg_hs_lock();
			peer = peer_lookup_by_handshake(device, msg_cookie->receiver);
			if (peer) {
				// Do NOT update the peer endpoint here: a cookie reply is not proof
				// of a live session (wireguard-go doesn't roam on it either).
				// Don't send anything out - we stay quiet until the next initiation message
				(void)wireguard_process_cookie_message(device, peer, msg_cookie);
			}
			wg_hs_unlock();
			break;

		case MESSAGE_TRANSPORT_DATA:
			msg_data = (struct message_transport_data *)data;
			peer = peer_lookup_by_receiver(device, msg_data->receiver);
			if (peer) {
				// header is 16 bytes long so take that off the length
				wireguardif_process_data_message(device, peer, msg_data, len - 16, addr, port);
			}
			break;

		default:
			// Unknown or bad packet header
			break;
	}
	// Release data!
	pbuf_free(p);
}

static err_t wireguard_start_handshake(struct netif *netif, struct wireguard_peer *peer) {
	if (!netif || !netif->state) {
		return ERR_ARG;
	}
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	err_t result;
	struct pbuf *pbuf;
	struct message_handshake_initiation msg;
	struct wg_peer_dest dest;

	// Handshake state (and the X25519 work) under the handshake lock; the
	// packet goes out after unlocking.
	wg_hs_lock();
	bool created = wireguard_create_handshake_initiation(device, peer, &msg);
	if (created) {
		// Handshake-control fields (send_handshake, last_initiation_tx,
		// handshake_attempts, active) are written under the state lock
		// everywhere else; tcpip_thread sets send_handshake from the TX path.
		wg_state_lock();
		peer->send_handshake = false;
		peer->last_initiation_tx = wireguard_sys_now();
		peer->handshake_attempts++;
		wg_state_unlock();
		memcpy(peer->handshake_mac1, msg.mac1, WIREGUARD_COOKIE_LEN);
		peer->handshake_mac1_valid = true;
	}
	wg_hs_unlock();
	if (!created) {
		ESP_LOGW(WG_TAG, "Could not create handshake initiation, result=%d", ERR_ARG);
		return ERR_ARG;
	}

	wg_peer_dest_snapshot(peer, &dest);
	WG_DEBUG("[WG_TX] Starting handshake to %s:%u",
		ip_addr_isany(&dest.ip) ? "DERP" : ipaddr_ntoa(&dest.ip), dest.port);

	pbuf = wireguardif_msg_pbuf(&msg, sizeof(msg));
	if (pbuf) {
		result = wireguardif_dest_output(netif, pbuf, &dest);
		ESP_LOGD(WG_TAG, "Handshake initiation sent, result=%d, sender_idx=%lu, to %s:%u",
			result, (unsigned long)msg.sender,
			ip_addr_isany(&dest.ip) ? "DERP" : ipaddr_ntoa(&dest.ip), dest.port);
		pbuf_free(pbuf);
	} else {
		result = ERR_MEM;
		ESP_LOGW(WG_TAG, "Could not create handshake initiation, result=%d", result);
	}
	return result;
}

static err_t wireguardif_lookup_peer(struct netif *netif, u8_t peer_index, struct wireguard_peer **out) {
	LWIP_ASSERT("netif != NULL", (netif != NULL));
	LWIP_ASSERT("state != NULL", (netif->state != NULL));
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	struct wireguard_peer *peer = NULL;
	err_t result;

	if (device->valid) {
		peer = peer_lookup_by_peer_index(device, peer_index);
		if (peer) {
			result = ERR_OK;
		} else {
			result = ERR_ARG;
		}
	} else {
		result = ERR_ARG;
	}
	*out = peer;
	return result;
}

err_t wireguardif_connect(struct netif *netif, u8_t peer_index) {
	struct wireguard_peer *peer;
	err_t result = wireguardif_lookup_peer(netif, peer_index, &peer);
	if (result == ERR_OK) {
		// Check that a valid connect ip and port have been set
		wg_state_lock();
		bool have_endpoint = !ip_addr_isany(&peer->connect_ip) && (peer->connect_port > 0);
		if (have_endpoint) {
			// Set the flag that we want to try connecting
			peer->active = true;
			peer->ip = peer->connect_ip;
			peer->port = peer->connect_port;
			// Force immediate handshake to the new endpoint
			peer->send_handshake = true;
			peer->last_initiation_tx = 0;
			// A fresh connect request starts a new give-up cycle - see
			// MAX_TIMER_HANDSHAKES in should_send_initiation().
			peer->handshake_attempts = 0;
		}
		wg_state_unlock();
		if (have_endpoint) {
			wireguard_start_handshake(netif, peer);
			result = ERR_OK;
		} else {
			result = ERR_ARG;
		}
	}
	return result;
}

err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port) {
	struct wireguard_peer *peer;
	err_t result = wireguardif_lookup_peer(netif, peer_index, &peer);
	if (result == ERR_OK) {
		wg_state_lock();
		// Up means TX has a usable keypair (the same test the output path and
		// the route tie-break use), not merely that some key material exists:
		// a peer whose curr keypair expired keeps a valid prev that TX never
		// uses, and reporting it up stopped callers from re-handshaking.
		if (wg_peer_can_send(peer)) {
			result = ERR_OK;
		} else {
			result = ERR_CONN;
		}
		if (current_ip) {
			*current_ip = peer->ip;
		}
		if (current_port) {
			*current_port = peer->port;
		}
		wg_state_unlock();
	}
	return result;
}

err_t wireguardif_remove_peer(struct netif *netif, u8_t peer_index) {
	struct wireguard_peer *peer;
	err_t result = wireguardif_lookup_peer(netif, peer_index, &peer);
	if (result == ERR_OK) {
		// Both locks: a send racing the wipe must never seal a packet under a
		// half-zeroed key or address it to a half-zeroed public key.
		wg_hs_lock();
		wg_state_lock();
		crypto_zero(peer, sizeof(struct wireguard_peer));
		peer->valid = false;
		wg_state_unlock();
		wg_hs_unlock();
		result = ERR_OK;
	}
	return result;
}

void wireguardif_shutdown(struct netif *netif) {
	if (!netif || !netif->state) {
		return;
	}
	struct wireguard_device *device = (struct wireguard_device *)netif->state;

	// Cancel the periodic timer BEFORE freeing any resources
	// This prevents use-after-free in wireguardif_tmr callback
	sys_untimeout(wireguardif_tmr, device);
}

void wireguardif_free(struct netif *netif) {
	if (!netif || !netif->state) {
		return;
	}
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	netif->state = NULL;

	// Idempotent with wireguardif_shutdown: untimeout of a timer that is not
	// armed is a no-op.
	sys_untimeout(wireguardif_tmr, device);
	if (device->udp_pcb) {
		udp_remove(device->udp_pcb);
		device->udp_pcb = NULL;
	}
	// The device holds the private key and every peer's session keys.
	crypto_zero(device, sizeof(struct wireguard_device));
	mem_free(device);
}

err_t wireguardif_update_endpoint(struct netif *netif, u8_t peer_index, const ip_addr_t *ip, u16_t port) {
	struct wireguard_peer *peer;
	err_t result = wireguardif_lookup_peer(netif, peer_index, &peer);
	if (result == ERR_OK && !ip_addr_isany(ip) && !wg_endpoint_usable(ip)) {
		result = ERR_ARG;
	}
	if (result == ERR_OK) {
		wg_state_lock();
		peer->connect_ip = *ip;
		peer->connect_port = port;
		wg_state_unlock();
		result = ERR_OK;
	}
	return result;
}

err_t wireguardif_set_endpoint(struct netif *netif, u8_t peer_index, const ip_addr_t *ip, u16_t port) {
	struct wireguard_peer *peer;
	err_t result = wireguardif_lookup_peer(netif, peer_index, &peer);
	if (result == ERR_OK && !ip_addr_isany(ip) && !wg_endpoint_usable(ip)) {
		result = ERR_ARG;
	}
	if (result == ERR_OK) {
		// Address only: no handshake, no change to send_handshake/active
		// (wg_mgr calls this on every heartbeat where the peer has roamed the
		// endpoint away from the best path).
		wg_state_lock();
		peer->connect_ip = *ip;
		peer->connect_port = port;
		peer->ip = *ip;
		peer->port = port;
		wg_state_unlock();
	}
	return result;
}

err_t wireguardif_add_peer(struct netif *netif, struct wireguardif_peer *p, u8_t *peer_index) {
	LWIP_ASSERT("netif != NULL", (netif != NULL));
	LWIP_ASSERT("state != NULL", (netif->state != NULL));
	LWIP_ASSERT("p != NULL", (p != NULL));
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	err_t result;
	uint8_t public_key[WIREGUARD_PUBLIC_KEY_LEN];
	size_t public_key_len = sizeof(public_key);
	struct wireguard_peer *peer = NULL;

	if (wireguard_base64_decode(p->public_key, public_key, &public_key_len)
			&& (public_key_len == WIREGUARD_PUBLIC_KEY_LEN)) {

		// See if the peer is already registered
		peer = peer_lookup_by_pubkey(device, public_key);
		if (!peer) {
			// Not active - see if we have room to allocate a new one
			peer = peer_alloc(device);
			if (peer) {

				// The slot is free (valid == false), so nothing else uses it; it is
				// published below, under the state lock, once fully set up.
				wg_hs_lock();
				bool init_ok = wireguard_peer_init(device, peer, public_key, p->preshared_key);
				if (init_ok) {
					peer->valid = false;
				}
				wg_hs_unlock();
				if (init_ok) {

					peer->connect_ip = p->endpoint_ip;
					peer->connect_port = p->endport_port;
					peer->ip = peer->connect_ip;
					peer->port = peer->connect_port;
					if (p->keep_alive == WIREGUARDIF_KEEPALIVE_DEFAULT) {
						peer->keepalive_interval = KEEPALIVE_TIMEOUT;
					} else {
						peer->keepalive_interval = p->keep_alive;
					}
					peer_add_ip(peer, p->allowed_ip, p->allowed_mask);
					memcpy(peer->greatest_timestamp, p->greatest_timestamp, sizeof(peer->greatest_timestamp));

					wg_state_lock();
					peer->valid = true;
					wg_state_unlock();
					result = ERR_OK;
				} else {
					result = ERR_ARG;
				}
			} else {
				result = ERR_MEM;
			}
		} else {
			result = ERR_OK;
		}
	} else {
		result = ERR_ARG;
	}

	if (peer_index) {
		if (peer) {
			*peer_index = wireguard_peer_index(device, peer);
		} else {
			*peer_index = WIREGUARDIF_INVALID_INDEX;
		}
	}
	return result;
}

static bool should_send_initiation(struct wireguard_peer *peer) {
	bool result = false;
	if (wireguardif_can_send_initiation(peer)) {
		if (peer->send_handshake) {
			result = true;
		} else if (peer->curr_keypair.valid && !peer->curr_keypair.initiator && wireguard_expired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME - peer->keepalive_interval)) {
			result = true;
		} else if (!peer->curr_keypair.valid && peer->active) {
			// Cap the "no session yet, actively retrying" case at
			// MAX_TIMER_HANDSHAKES attempts (~REKEY_ATTEMPT_TIME seconds),
			// matching wireguard-go's give-up behavior - see
			// REKEY_ATTEMPT_TIME in wireguard.h. Handshakes explicitly
			// re-requested by send_handshake (rekey of an already-
			// established session) are not capped here.
			if (peer->handshake_attempts >= MAX_TIMER_HANDSHAKES) {
				peer->active = false;
			} else {
				result = true;
			}
		}
	}
	return result;
}

static bool should_send_keepalive(struct wireguard_peer *peer) {
	bool result = false;
	if (peer->keepalive_interval > 0) {
		if ((peer->curr_keypair.valid) || (peer->prev_keypair.valid)) {
			if (wireguard_expired(peer->last_tx, peer->keepalive_interval)) {
				result = true;
			}
		}
	}
	return result;
}

static bool should_destroy_current_keypair(struct wireguard_peer *peer) {
	bool result = false;
	if (peer->curr_keypair.valid &&
			(wireguard_expired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME) ||
			(peer->curr_keypair.sending_counter >= REJECT_AFTER_MESSAGES))
		) {
		result = true;
	}
	return result;
}

static bool should_reset_peer(struct wireguard_peer *peer) {
	bool result = false;
	if (peer->curr_keypair.valid && (wireguard_expired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME * 3))) {
		result = true;
	}
	return result;
}

// Keepalive / rekey / expiry work for one peer, shared by the tcpip_thread
// timer and wireguardif_periodic(). Returns true if the peer has keys.
static bool wireguardif_service_peer(struct wireguard_device *device, struct wireguard_peer *peer, int idx) {
	bool keepalive;
	bool initiate;
	bool has_keys;

	wg_state_lock();
	// Do we need to rekey / send a handshake?
	if (should_reset_peer(peer)) {
		// Nothing back for too long - we should wipe out all crypto state
		keypair_destroy(&peer->next_keypair);
		keypair_destroy(&peer->curr_keypair);
		keypair_destroy(&peer->prev_keypair);
		// TODO: Also destroy handshake?

		// Revert back to default IP/port if these were altered
		peer->ip = peer->connect_ip;
		peer->port = peer->connect_port;
	}
	if (should_destroy_current_keypair(peer)) {
		// Destroy current keypair
		keypair_destroy(&peer->curr_keypair);
	}
	keepalive = should_send_keepalive(peer);
	initiate = should_send_initiation(peer);
	wg_state_unlock();

	if (keepalive) {
		wireguardif_send_keepalive(device, peer);
	}
	if (initiate) {
		if (LOG_LOCAL_LEVEL >= ESP_LOG_DEBUG && esp_log_level_get(WG_TAG) >= ESP_LOG_DEBUG) {
			// ipaddr_ntoa() has one static buffer, so format both addresses separately
			char ip_str[IPADDR_STRLEN_MAX], connect_str[IPADDR_STRLEN_MAX];
			ipaddr_ntoa_r(&peer->ip, ip_str, sizeof(ip_str));
			ipaddr_ntoa_r(&peer->connect_ip, connect_str, sizeof(connect_str));
			ESP_LOGD(WG_TAG, "Handshake retry wg_idx=%d key=%02x%02x%02x%02x "
			       "ip=%s:%u connect_ip=%s:%u active=%d send_hs=%d",
			       idx,
			       peer->public_key[0], peer->public_key[1],
			       peer->public_key[2], peer->public_key[3],
			       ip_str, peer->port, connect_str, peer->connect_port,
			       peer->active, peer->send_handshake);
		}
		wireguard_start_handshake(device->netif, peer);
	}

	wg_state_lock();
	has_keys = (peer->curr_keypair.valid) || (peer->prev_keypair.valid);
	wg_state_unlock();
	return has_keys;
}

static void wireguardif_tmr(void *arg) {
	struct wireguard_device *device = (struct wireguard_device *)arg;
	if (!device || !device->netif) {
		// Device was freed or netif is invalid - don't reschedule
		return;
	}
	int x;
	// Reschedule this timer
	sys_timeout(WIREGUARDIF_TIMER_MSECS, wireguardif_tmr, device);

	// Check periodic things
	bool link_up = false;
	for (x=0; x < WIREGUARD_MAX_PEERS; x++) {
		if (device->peers[x].valid && wireguardif_service_peer(device, &device->peers[x], x)) {
			link_up = true;
		}
	}

	if (!link_up) {
		// Clear the IF-UP flag on netif
		wireguardif_mark_link_down(device->netif);
	}
}

void wireguardif_periodic(struct netif *netif) {
	if (!netif || !netif->state) {
		return;
	}
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	int x;

	// Perform the same work as wireguardif_tmr but from the caller's task context,
	// avoiding heavy crypto (X25519, ChaCha20-Poly1305) on the lwIP TCPIP thread.
	bool link_up = false;
	for (x = 0; x < WIREGUARD_MAX_PEERS; x++) {
		if (device->peers[x].valid && wireguardif_service_peer(device, &device->peers[x], x)) {
			link_up = true;
		}
	}
	if (!link_up) {
		wireguardif_mark_link_down(device->netif);
	}
}

err_t wireguardif_init(struct netif *netif) {
	err_t result;
	if (!s_wg_tx_lock) {
		s_wg_tx_lock = xSemaphoreCreateMutexStatic(&s_wg_tx_lock_buf);
	}
	if (!s_wg_hs_lock) {
		s_wg_hs_lock = xSemaphoreCreateMutexStatic(&s_wg_hs_lock_buf);
	}
	struct wireguardif_init_data *init_data;
	struct wireguard_device *device;
	struct udp_pcb *udp;
	uint8_t private_key[WIREGUARD_PRIVATE_KEY_LEN];
	size_t private_key_len = sizeof(private_key);

	LWIP_ASSERT("netif != NULL", (netif != NULL));
	LWIP_ASSERT("state != NULL", (netif->state != NULL));

	// We need to initialise the wireguard module
	wireguard_init();

	if (netif && netif->state) {

		// The init data is passed into the netif_add call as the 'state' - we will replace this with our private state data
		init_data = (struct wireguardif_init_data *)netif->state;

		// Clear out and set if function is successful
		netif->state = NULL;

		if (wireguard_base64_decode(init_data->private_key, private_key, &private_key_len)
				&& (private_key_len == WIREGUARD_PRIVATE_KEY_LEN)) {

			// In magicsock mode, skip creating UDP socket - packets come via wireguardif_network_rx
			if (g_disable_socket_bind) {
				WG_DEBUG("[WG] Socket binding disabled - using magicsock mode");
				device = (struct wireguard_device *)mem_calloc(1, sizeof(struct wireguard_device));
				if (device) {
					device->netif = netif;
					device->udp_pcb = NULL;  // No internal socket
					if (wireguard_device_init(device, private_key)) {
#if LWIP_CHECKSUM_CTRL_PER_NETIF
						NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_ENABLE_ALL);
#endif
						netif->state = device;
						netif->name[0] = 'w';
						netif->name[1] = 'g';
						netif->output = wireguardif_output;
#if LWIP_IPV6
						netif->output_ip6 = wireguardif_output_ip6;
#endif
						netif->linkoutput = NULL;
						netif->hwaddr_len = 0;
						netif->mtu = WIREGUARDIF_MTU;
						netif->flags = 0;

						// In magicsock mode, DON'T start the periodic timer on the TCPIP thread.
						// The heavy crypto (X25519, ChaCha20-Poly1305) for handshakes can take
						// 5-20ms per peer. With 11+ peers, this monopolizes the TCPIP thread
						// for 55-220ms, blocking ALL socket operations system-wide.
						// Instead, the caller should use wireguardif_periodic() from their own task.
						// sys_timeout(WIREGUARDIF_TIMER_MSECS, wireguardif_tmr, device);

						result = ERR_OK;
					} else {
						mem_free(device);
						device = NULL;
						result = ERR_ARG;
					}
				} else {
					result = ERR_MEM;
				}
			} else {
				// Normal mode - create and bind UDP socket
				udp = udp_new();

				if (udp) {
					result = udp_bind(udp, IP_ADDR_ANY, init_data->listen_port); // Note this listens on all interfaces! Really just want the passed netif
					if (result == ERR_OK) {
						device = (struct wireguard_device *)mem_calloc(1, sizeof(struct wireguard_device));
						if (device) {
							device->netif = netif;
							if (init_data->bind_netif) {
								udp_bind_netif(udp, init_data->bind_netif);
							}
							device->udp_pcb = udp;
							// Per-wireguard netif/device setup
							if (wireguard_device_init(device, private_key)) {
#if LWIP_CHECKSUM_CTRL_PER_NETIF
								NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_ENABLE_ALL);
#endif
								netif->state = device;
								netif->name[0] = 'w';
								netif->name[1] = 'g';
								netif->output = wireguardif_output;
#if LWIP_IPV6
								netif->output_ip6 = wireguardif_output_ip6;
#endif
								netif->linkoutput = NULL;
								netif->hwaddr_len = 0;
								netif->mtu = WIREGUARDIF_MTU;
								// We set up no state flags here - caller should set them
								// NETIF_FLAG_LINK_UP is automatically set/cleared when at least one peer is connected
								netif->flags = 0;

								udp_recv(udp, wireguardif_network_rx, device);

								// Start a periodic timer for this wireguard device
								sys_timeout(WIREGUARDIF_TIMER_MSECS, wireguardif_tmr, device);

								result = ERR_OK;
							} else {
								mem_free(device);
								device = NULL;
								udp_remove(udp);
								result = ERR_ARG;
							}
						} else {
							udp_remove(udp);
							result = ERR_MEM;
						}
					} else {
						udp_remove(udp);
					}

				} else {
					result = ERR_MEM;
				}
			}
		} else {
			result = ERR_ARG;
		}
	} else {
		result = ERR_ARG;
	}
	return result;
}

void wireguardif_peer_init(struct wireguardif_peer *peer) {
	LWIP_ASSERT("peer != NULL", (peer != NULL));
	memset(peer, 0, sizeof(struct wireguardif_peer));
	// Caller must provide 'public_key'
	peer->public_key = NULL;
	ip_addr_set_any(0, &peer->endpoint_ip);
	peer->endport_port = WIREGUARDIF_DEFAULT_PORT;
	peer->keep_alive = WIREGUARDIF_KEEPALIVE_DEFAULT;
	ip_addr_set_any(0, &peer->allowed_ip);
	ip_addr_set_any(0, &peer->allowed_mask);
	memset(peer->greatest_timestamp, 0, sizeof(peer->greatest_timestamp));
	peer->preshared_key = NULL;
}

void wireguardif_set_ip_filter(struct netif *netif, wireguard_ip_filter_fn rx_allow,
                               wireguard_ip_note_fn tx_note, void *ctx) {
	LWIP_ASSERT("netif != NULL", (netif != NULL));
	LWIP_ASSERT("state != NULL", (netif->state != NULL));
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	if (device->valid) {
		device->filter_ctx = ctx;
		device->tx_note_fn = tx_note;
		device->rx_filter_fn = rx_allow;
	}
}

void wireguardif_set_derp_output(struct netif *netif, wireguard_derp_output_fn fn, void *ctx) {
	LWIP_ASSERT("netif != NULL", (netif != NULL));
	LWIP_ASSERT("state != NULL", (netif->state != NULL));
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	if (device->valid) {
		device->derp_output_fn = fn;
		device->derp_output_ctx = ctx;
	}
}

void wireguardif_set_udp_output(struct netif *netif, wireguard_udp_output_fn fn, void *ctx) {
	LWIP_ASSERT("netif != NULL", (netif != NULL));
	LWIP_ASSERT("state != NULL", (netif->state != NULL));
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	if (device->valid) {
		device->udp_output_fn = fn;
		device->udp_output_ctx = ctx;
		WG_DEBUG("[WG] UDP output callback registered (magicsock mode)");
	}
}

void wireguardif_set_udp_output_pbuf(struct netif *netif, wireguard_udp_output_pbuf_fn fn, void *ctx) {
	LWIP_ASSERT("netif != NULL", (netif != NULL));
	LWIP_ASSERT("state != NULL", (netif->state != NULL));
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	if (device->valid) {
		device->udp_output_pbuf_fn = fn;
		device->udp_output_pbuf_ctx = ctx;
		WG_DEBUG("[WG] zero-copy UDP output callback registered");
	}
}

void wireguardif_detach_outputs(struct netif *netif) {
	if (!netif || !netif->state) {
		return;
	}
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	// Pointers first, then contexts: a sender that already loaded a pointer
	// sees either the old context (still alive when this is called) or NULL.
	__atomic_store_n(&device->derp_output_fn, NULL, __ATOMIC_RELEASE);
	__atomic_store_n(&device->udp_output_pbuf_fn, NULL, __ATOMIC_RELEASE);
	__atomic_store_n(&device->udp_output_fn, NULL, __ATOMIC_RELEASE);
	__atomic_store_n(&device->derp_output_ctx, NULL, __ATOMIC_RELEASE);
	__atomic_store_n(&device->udp_output_pbuf_ctx, NULL, __ATOMIC_RELEASE);
	__atomic_store_n(&device->udp_output_ctx, NULL, __ATOMIC_RELEASE);
}

void wireguardif_force_derp_output(struct netif *netif, bool force) {
	LWIP_ASSERT("netif != NULL", (netif != NULL));
	LWIP_ASSERT("state != NULL", (netif->state != NULL));
	struct wireguard_device *device = (struct wireguard_device *)netif->state;
	if (device->valid) {
		device->force_derp_output = force;
		ESP_LOGD(WG_TAG, "force_derp_output=%d", force);
	}
}

err_t wireguardif_connect_derp(struct netif *netif, u8_t peer_index) {
	struct wireguard_peer *peer;
	err_t result = wireguardif_lookup_peer(netif, peer_index, &peer);
	if (result == ERR_OK) {
		wg_state_lock();
		// Mark peer as active so timer will initiate handshakes
		peer->active = true;
		// Force immediate handshake by setting send_handshake flag
		peer->send_handshake = true;
		// CRITICAL: Clear endpoint IP/port to force DERP relay output!
		// Without this, wireguardif_dest_output() will try UDP to old endpoint
		ip_addr_set_any(false, &peer->ip);
		peer->port = 0;
		// Force immediate handshake - clear last_initiation_tx to bypass REKEY_TIMEOUT
		// This is safe because DISCO has confirmed the path works
		peer->last_initiation_tx = 0;
		// A fresh connect-via-DERP request starts a new give-up cycle -
		// see MAX_TIMER_HANDSHAKES in should_send_initiation(). Without
		// this, a peer that never actually responds (e.g. has trimmed us,
		// or the DERP path itself is bad) gets a handshake retried every
		// REKEY_TIMEOUT (5s) forever - nothing else in this function or
		// its caller (wireguardif_periodic()'s own timer loop) ever
		// clears peer->active if the session never establishes.
		peer->handshake_attempts = 0;
		wg_state_unlock();
		// Now start handshake immediately
		wireguard_start_handshake(netif, peer);
		result = ERR_OK;
	}
	return result;
}
