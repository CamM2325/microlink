/*
 * ml_nat66: IPv6 masquerading for an exit node.
 *
 * Tailscale exit nodes NAT IPv6 as they do IPv4: traffic from a peer's
 * tailnet address (fd7a:115c:a1e0::/48, not routable on the internet) leaves
 * with the exit node's own global address. lwIP has NAT only for IPv4, so
 * this does it for IPv6: TCP and UDP by port, ICMPv6 echo by identifier,
 * with endpoint-independent mappings and incrementally updated checksums.
 *
 * The core works on packet bytes (host-tested). On the device it runs in
 * lwIP's IPv6 input hook (CONFIG_LWIP_HOOK_IP6_INPUT_CUSTOM), on
 * tcpip_thread only, so it needs no lock.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ML_NAT66_SLOTS    256
#define ML_NAT66_PORT_LO  32768   /* mapped ports: below lwIP's ephemeral range */
#define ML_NAT66_PORT_HI  49151

/* Forget every mapping. */
void ml_nat66_reset(void);

/* Tunnel -> internet. pkt holds the IPv6 header and the transport header
 * (len bytes). Replaces the source with lan_addr and the source port (or
 * ICMPv6 echo identifier) with a mapped one, fixing the checksum.
 * Returns 0 when translated, -1 when the packet cannot be (drop it). */
int ml_nat66_out(uint8_t *pkt, size_t len, const uint8_t lan_addr[16], uint32_t now_ms);

/* Internet -> tunnel. If the packet is addressed to a mapping, restores the
 * peer's address and port and returns 1; otherwise leaves it and returns 0. */
int ml_nat66_in(uint8_t *pkt, size_t len, uint32_t now_ms);

/* Number of mappings in use (for tests and diagnostics). */
int ml_nat66_count(uint32_t now_ms);

#ifdef ESP_PLATFORM
struct netif;
/* Translate between this WireGuard netif and the LAN (tcpip_thread only).
 * NULL detaches and clears the table. */
void ml_nat66_attach(struct netif *wg_netif);
#endif

#ifdef __cplusplus
}
#endif
