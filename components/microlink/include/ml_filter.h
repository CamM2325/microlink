/*
 * ml_filter: on-device enforcement of the tailnet packet filter (ACLs).
 *
 * The control plane sends the tailnet policy as MapResponse.PacketFilter
 * (array of tailcfg.FilterRule) or, on newer servers, PacketFilters (map of
 * named rule sets). Like Tailscale's wgengine/filter, inbound packets from
 * the tunnel are accepted only if a rule allows them:
 *   - TCP: only new connections (SYN without ACK) are checked; other TCP
 *     packets belong to connections that had to start with a checked SYN.
 *   - UDP: replies to flows this device started are accepted (flow table).
 *   - ICMP: echo replies and errors are accepted; other ICMP needs a rule.
 * Until the first policy arrives nothing new is accepted (replies and ICMP
 * errors are), like Tailscale's initial allow-nothing filter. A rule set
 * that cannot be applied (malformed, too large) allows nothing.
 *
 * Independently of the policy (in every mode, including OFF), inbound
 * packets must be addressed to the device's tailnet IP or to one of its
 * advertised subnet routes; anything else is dropped, like Tailscale's
 * "destination not allowed". This keeps a peer from using a subnet router
 * to reach addresses it does not advertise.
 *
 * The core is pure C (plus cJSON) so it can be unit-tested on a PC.
 */
#ifndef ML_FILTER_H
#define ML_FILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ml_routes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ML_FILTER_MODE_OFF = 0,     /* accept everything (legacy behaviour) */
    ML_FILTER_MODE_LOG,         /* evaluate and log, but accept */
    ML_FILTER_MODE_ENFORCE,     /* drop what the policy doesn't allow */
} ml_filter_mode_t;

typedef struct {
    uint32_t accepted;
    uint32_t dropped;           /* would-drop count in LOG mode */
    uint32_t rules;             /* rules in the active policy */
    bool     configured;        /* a policy has been received */
} ml_filter_stats_t;

struct cJSON;

/* Set up the filter (idempotent). */
void ml_filter_init(ml_filter_mode_t mode);
/* Free the policy and flow state (e.g. on microlink_destroy). */
void ml_filter_reset(void);

/*
 * Apply the filter fields of one MapResponse (full or delta):
 * "PacketFilter" absent = unchanged, present = replaces the "base" set;
 * "PacketFilters" {name: rules|null} updates named sets (null deletes).
 * Returns true if the active policy changed. A policy that cannot be
 * parsed or exceeds limits leaves the previous one in place.
 */
bool ml_filter_update_from_map(const struct cJSON *map_response);

/*
 * Addresses the device accepts traffic for: its tailnet IP (host byte
 * order) and its advertised routes. Until self_ip is set (non-zero) no
 * destination check is made. The routes are copied.
 */
void ml_filter_set_local(uint32_t self_ip, const ml_route_t *routes, int n);

/*
 * IPv6: the device's tailnet IPv6 address (16 bytes, NULL = none: all IPv6
 * from the tunnel is dropped), whether it forwards IPv6 to the internet as
 * an exit node (then any destination outside the tailnet range, link-local
 * and multicast is local too) and its advertised IPv6 routes (copied).
 * Policies' IPv6 entries are enforced like the IPv4 ones.
 */
void ml_filter_set_local6(const uint8_t self6[16], bool exit_node, const ml_route6_t *routes, int n);

/*
 * Inbound IPv4 packet from the tunnel (full IP packet, len bytes).
 * Returns true if it may be delivered.
 */
bool ml_filter_check_inbound(const uint8_t *pkt, size_t len, uint32_t now_ms);

/* Outbound IPv4 packet into the tunnel (at least the first 28 bytes):
 * records UDP flows so replies are accepted. */
void ml_filter_note_outbound(const uint8_t *pkt, size_t len, uint32_t now_ms);

void ml_filter_get_stats(ml_filter_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ML_FILTER_H */
