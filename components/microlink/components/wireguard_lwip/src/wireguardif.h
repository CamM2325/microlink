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


#ifndef _WIREGUARDIF_H_
#define _WIREGUARDIF_H_

#include "lwip/arch.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "wireguard.h"  // For wireguard_derp_output_fn typedef

// Default MTU for WireGuard is 1420 bytes
#define WIREGUARDIF_MTU (1420)

#define WIREGUARDIF_DEFAULT_PORT		(51820)
#define WIREGUARDIF_KEEPALIVE_DEFAULT	(0xFFFF)

struct wireguardif_init_data {
	// Required: the private key of this WireGuard network interface
	const char *private_key;
	// Required: What UDP port to listen on
	u16_t listen_port;
	// Optional: restrict send/receive of encapsulated WireGuard traffic to this network interface only (NULL to use routing table)
	struct netif *bind_netif;
};

struct wireguardif_peer {
	const char *public_key;
	// Optional pre-shared key (32 bytes) - make sure this is NULL if not to be used
	const uint8_t *preshared_key;
	// tai64n of largest timestamp we have seen during handshake to avoid replays
	uint8_t greatest_timestamp[12];

	// Allowed ip/netmask (can add additional later but at least one is required)
	ip_addr_t allowed_ip;
	ip_addr_t allowed_mask;

	// End-point details (may be blank)
	ip_addr_t endpoint_ip;
	u16_t endport_port;
	u16_t keep_alive;
};

#define WIREGUARDIF_INVALID_INDEX (0xFF)

/* static struct netif wg_netif_struct = {0};
 * struct wireguard_interface wg;
 * wg.private_key = "abcdefxxx..xxxxx=";
 * wg.listen_port = 51820;
 * wg.bind_netif = NULL; // Pass netif to listen on, NULL for all interfaces
 *
 * netif = netif_add(&netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);
 *
 * netif_set_up(wg_net);
 *
 * struct wireguardif_peer peer;
 * wireguardif_peer_init(&peer);
 * peer.public_key = "apoehc...4322abcdfejg=;
 * peer.preshared_key = NULL;
 * peer.allowed_ip = allowed_ip;
 * peer.allowed_mask = allowed_mask;
 *
 * // If you want to enable output connection
 * peer.endpoint_ip = peer_ip;
 * peer.endport_port = 12345;
 *
 * uint8_t wireguard_peer_index;
 * wireguardif_add_peer(netif, &peer, &wireguard_peer_index);
 *
 * if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
 *   // Start outbound connection to peer
 *   wireguardif_connect(wg_net, wireguard_peer_index);
 * }
 *
 */

// Initialise a new WireGuard network interface (netif)
err_t wireguardif_init(struct netif *netif);

// Helper to initialise the peer struct with defaults
void wireguardif_peer_init(struct wireguardif_peer *peer);

// Add a new peer to the specified interface - see wireguard.h for maximum number of peers allowed
// On success the peer_index can be used to reference this peer in future function calls
err_t wireguardif_add_peer(struct netif *netif, struct wireguardif_peer *peer, u8_t *peer_index);

// Remove the given peer from the network interface
err_t wireguardif_remove_peer(struct netif *netif, u8_t peer_index);

// Update the "connect" IP of the given peer
err_t wireguardif_update_endpoint(struct netif *netif, u8_t peer_index, const ip_addr_t *ip, u16_t port);

// Try and connect to the given peer
err_t wireguardif_connect(struct netif *netif, u8_t peer_index);

// Stop trying to connect to the given peer
err_t wireguardif_disconnect(struct netif *netif, u8_t peer_index);

// Is the given peer "up"? A peer is up if it has a valid session key it can communicate with
err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port);

// Register a DERP relay output callback for peers without direct endpoints
// This callback is invoked when a WireGuard packet needs to be sent to a peer
// that has no direct IP endpoint (ip is 0.0.0.0 or port is 0)
// fn: callback function, ctx: user context passed to callback
void wireguardif_set_derp_output(struct netif *netif, wireguard_derp_output_fn fn, void *ctx);

// Force initiation of handshake to a DERP-only peer
// Use this for peers where connect() would fail due to no direct endpoint
// The handshake will be routed through the DERP callback if set
err_t wireguardif_connect_derp(struct netif *netif, u8_t peer_index);

// Inject a received packet into the WireGuard interface (for magicsock demux)
// This allows an external unified socket to receive all packets and route
// WireGuard packets to this interface. The packet data is copied internally.
// src_ip: source IP in network byte order (0 for DERP)
// src_port: source port in host byte order
// data: raw packet data
// len: packet length
err_t wireguardif_inject_packet(struct netif *netif, uint32_t src_ip, uint16_t src_port,
                                 const uint8_t *data, size_t len);

// Check if packet looks like a WireGuard packet (type 1-4)
// Returns true if this appears to be a WireGuard packet
bool wireguardif_is_wireguard_packet(const uint8_t *data, size_t len);

// Shutdown WireGuard interface - cancels all timers before freeing resources
// MUST be called before netif_remove/mem_free to prevent use-after-free in wireguardif_tmr
void wireguardif_shutdown(struct netif *netif);

// Run WireGuard periodic processing (handshakes, keepalives, rekeys) from caller's task.
// In magicsock mode, the internal sys_timeout timer is disabled to avoid running heavy
// crypto (X25519, ChaCha20-Poly1305) on the lwIP TCPIP thread. Call this every ~400ms.
void wireguardif_periodic(struct netif *netif);

// Disable WireGuard's internal UDP socket binding
// Call before wireguardif_init to prevent WireGuard from binding its own socket.
// The caller is then responsible for receiving packets and calling wireguardif_inject_packet.
void wireguardif_disable_socket_bind(void);

// Set the UDP output callback for magicsock mode
// When socket binding is disabled, this callback is used to send packets
// via an external unified socket instead of the internal lwIP UDP PCB.
void wireguardif_set_udp_output(struct netif *netif, wireguard_udp_output_fn fn, void *ctx);

/* Zero-copy variant. Takes precedence over wireguardif_set_udp_output() when
 * set; prefer it whenever the sender can consume a pbuf. */
void wireguardif_set_udp_output_pbuf(struct netif *netif, wireguard_udp_output_pbuf_fn fn, void *ctx);

// Force all peer output through DERP relay callback (cellular mode).
// When enabled, peer_output always uses DERP even if peer has a direct endpoint.
void wireguardif_force_derp_output(struct netif *netif, bool force);

#endif /* _WIREGUARDIF_H_ */
