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
 * Before the first filter arrives everything is accepted.
 *
 * The core is pure C (plus cJSON) so it can be unit-tested on a PC.
 */
#ifndef ML_FILTER_H
#define ML_FILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
