/**
 * @file ml_stun.c
 * @brief Async STUN Probe Implementation (Tailscale-compatible)
 *
 * Non-blocking STUN binding requests with async response parsing.
 * Probe is sent from coord task, response is received by net_io task
 * and delivered via stun_rx_queue.
 *
 * Matches Tailscale reference: SOFTWARE="tailnode", FINGERPRINT=CRC32^0x5354554e
 * Supports Tailscale STUN primary (derp*.tailscale.com:3478) + Google fallback.
 * DNS pre-resolution avoids blocking in hot path.
 *
 * Reference: tailscale/net/stun/stun.go
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_crc.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>
#include <errno.h>

static const char *TAG = "ml_stun";

/* STUN constants (RFC 5389) */
#define STUN_MAGIC_COOKIE               0x2112A442
#define STUN_HEADER_SIZE                20
#define STUN_BINDING_REQUEST            0x0001
#define STUN_BINDING_RESPONSE           0x0101
#define STUN_ATTR_XOR_MAPPED_ADDRESS    0x0020
#define STUN_ATTR_MAPPED_ADDRESS        0x0001
#define STUN_ATTR_SOFTWARE              0x8022
#define STUN_ATTR_FINGERPRINT           0x8028
#define STUN_FINGERPRINT_XOR            0x5354554e  /* ASCII "STUN" */

/* Tailscale SOFTWARE attribute value (exactly 8 bytes, no padding needed) */
static const char STUN_SOFTWARE[] = "tailnode";
#define STUN_SOFTWARE_LEN   8

/* Full request: 20 header + 12 SOFTWARE attr + 8 FINGERPRINT attr = 40 bytes */
#define STUN_REQUEST_SIZE   40

/* Attribute sizes */
#define STUN_ATTR_SOFTWARE_TOTAL    (4 + STUN_SOFTWARE_LEN)  /* 12 */
#define STUN_ATTR_FINGERPRINT_TOTAL 8                         /* 4 header + 4 value */

/* Forward declarations */
static esp_err_t ensure_stun_socket6(microlink_t *ml);

/* Separate transaction IDs for IPv4 and IPv6 (they race each other) */
static uint8_t txid_v4[12];
static bool txid_v4_valid = false;
static uint8_t txid_v6[12];
static bool txid_v6_valid = false;

/* ============================================================================
 * CRC32 FINGERPRINT (IEEE 802.3, matches Tailscale's crc32.ChecksumIEEE)
 * ========================================================================== */

static uint32_t stun_fingerprint(const uint8_t *data, size_t len) {
    uint32_t crc = esp_crc32_le(0, data, len);
    return crc ^ STUN_FINGERPRINT_XOR;
}

/* ============================================================================
 * STUN Request Builder (Tailscale-compatible: SOFTWARE + FINGERPRINT)
 * ========================================================================== */

static size_t build_stun_request(uint8_t *out, uint8_t *txid_out) {
    size_t pos = 0;

    /* Message Type: Binding Request (0x0001) */
    out[pos++] = 0x00;
    out[pos++] = 0x01;

    /* Message Length: attributes only (SOFTWARE + FINGERPRINT = 20 bytes) */
    uint16_t msg_len = STUN_ATTR_SOFTWARE_TOTAL + STUN_ATTR_FINGERPRINT_TOTAL;
    out[pos++] = (msg_len >> 8) & 0xFF;
    out[pos++] = msg_len & 0xFF;

    /* Magic Cookie */
    out[pos++] = 0x21;
    out[pos++] = 0x12;
    out[pos++] = 0xA4;
    out[pos++] = 0x42;

    /* Transaction ID: 12 random bytes */
    esp_fill_random(txid_out, 12);
    memcpy(out + pos, txid_out, 12);
    pos += 12;

    /* SOFTWARE attribute (type 0x8022) */
    out[pos++] = (STUN_ATTR_SOFTWARE >> 8) & 0xFF;
    out[pos++] = STUN_ATTR_SOFTWARE & 0xFF;
    out[pos++] = 0x00;
    out[pos++] = STUN_SOFTWARE_LEN;
    memcpy(out + pos, STUN_SOFTWARE, STUN_SOFTWARE_LEN);
    pos += STUN_SOFTWARE_LEN;

    /* FINGERPRINT attribute (type 0x8028) — CRC32 of everything before it */
    uint32_t fp = stun_fingerprint(out, pos);
    out[pos++] = (STUN_ATTR_FINGERPRINT >> 8) & 0xFF;
    out[pos++] = STUN_ATTR_FINGERPRINT & 0xFF;
    out[pos++] = 0x00;
    out[pos++] = 0x04;
    out[pos++] = (fp >> 24) & 0xFF;
    out[pos++] = (fp >> 16) & 0xFF;
    out[pos++] = (fp >> 8) & 0xFF;
    out[pos++] = fp & 0xFF;

    return pos;  /* Should be STUN_REQUEST_SIZE (40) */
}

/* ============================================================================
 * Socket Setup (shared between probe functions)
 * ========================================================================== */

static esp_err_t ensure_stun_socket(microlink_t *ml) {
    if (ml->stun_sock >= 0) return ESP_OK;

    ml->stun_sock = ml_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->stun_sock < 0) {
        ESP_LOGE(TAG, "Failed to create STUN socket: %d", errno);
        return ESP_FAIL;
    }

    /* Non-blocking */
    int flags = ml_fcntl(ml->stun_sock, F_GETFL, 0);
    ml_fcntl(ml->stun_sock, F_SETFL, flags | O_NONBLOCK);

    /* Bind to any port */
    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = INADDR_ANY,
    };
    ml_bind(ml->stun_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

    return ESP_OK;
}

/* ============================================================================
 * DNS Pre-Resolution
 * ========================================================================== */

esp_err_t ml_stun_resolve_servers(microlink_t *ml) {
    struct addrinfo *res = NULL;

    /* Determine primary STUN host — use parsed DERPMap home region if available */
    const char *primary_host = ML_STUN_PRIMARY_HOST;
    uint16_t primary_port = ML_STUN_PRIMARY_PORT;

    if (ml->derp_region_count > 0) {
        /* Find home region (derp_home_region) or fallback to first region */
        uint16_t target_region = ml->derp_home_region ? ml->derp_home_region : ML_DERP_REGION;
        for (int i = 0; i < ml->derp_region_count; i++) {
            if (ml->derp_regions[i].region_id == target_region &&
                ml->derp_regions[i].node_count > 0 &&
                ml->derp_regions[i].nodes[0].hostname[0]) {
                primary_host = ml->derp_regions[i].nodes[0].hostname;
                if (ml->derp_regions[i].nodes[0].stun_port > 0) {
                    primary_port = ml->derp_regions[i].nodes[0].stun_port;
                }
                /* If node has direct IPv4, use it to skip DNS */
                if (ml->stun_primary_ip == 0 && ml->derp_regions[i].nodes[0].ipv4[0]) {
                    unsigned a, b, c, d;
                    if (sscanf(ml->derp_regions[i].nodes[0].ipv4, "%u.%u.%u.%u",
                               &a, &b, &c, &d) == 4) {
                        ml->stun_primary_ip = (a << 24) | (b << 16) | (c << 8) | d;
                        char ip_str[16];
                        microlink_ip_to_str(ml->stun_primary_ip, ip_str);
                        ESP_LOGI(TAG, "STUN primary from DERPMap: %s:%u (region %d)",
                                 ip_str, primary_port, target_region);
                    }
                }
                break;
            }
        }
    }

    /* Resolve primary: Tailscale DERP STUN server (if not already resolved from DERPMap IPv4) */
    static const uint8_t zero16[16] = {0};
    if (ml->stun_primary_ip == 0 && memcmp(ml->stun_primary_ip6, zero16, 16) == 0) {
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%u", primary_port);
        /* Use AF_UNSPEC to accept whatever DNS returns (IPv4 or IPv6) */
        struct addrinfo hints_any = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM };
        if (ml_getaddrinfo(primary_host, port_str, &hints_any, &res) == 0 && res) {
            if (res->ai_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
                ml->stun_primary_ip = ntohl(addr->sin_addr.s_addr);
                char ip_str[16];
                microlink_ip_to_str(ml->stun_primary_ip, ip_str);
                ESP_LOGI(TAG, "STUN primary resolved: %s -> %s", primary_host, ip_str);
            } else if (res->ai_family == AF_INET6) {
                struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)res->ai_addr;
                memcpy(ml->stun_primary_ip6, &addr6->sin6_addr, 16);
                ESP_LOGI(TAG, "STUN primary resolved: %s -> IPv6 (carrier IPv6-only)",
                         primary_host);
            }
            ml_freeaddrinfo(res);
            res = NULL;
        } else {
            ESP_LOGW(TAG, "DNS resolve failed for %s", primary_host);
            if (res) ml_freeaddrinfo(res);
            res = NULL;
        }
    }

    /* Resolve fallback: Google STUN */
    if (ml->stun_fallback_ip == 0) {
        struct addrinfo hints_any = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM };
        if (ml_getaddrinfo(ML_STUN_FALLBACK_HOST, "19302", &hints_any, &res) == 0 && res) {
            if (res->ai_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
                ml->stun_fallback_ip = ntohl(addr->sin_addr.s_addr);
                char ip_str[16];
                microlink_ip_to_str(ml->stun_fallback_ip, ip_str);
                ESP_LOGI(TAG, "STUN fallback resolved: %s -> %s",
                         ML_STUN_FALLBACK_HOST, ip_str);
            } else if (res->ai_family == AF_INET6) {
                /* Store fallback IPv6 in primary IPv6 slot if primary is empty */
                if (memcmp(ml->stun_primary_ip6, zero16, 16) == 0) {
                    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)res->ai_addr;
                    memcpy(ml->stun_primary_ip6, &addr6->sin6_addr, 16);
                    ESP_LOGI(TAG, "STUN fallback resolved: %s -> IPv6",
                             ML_STUN_FALLBACK_HOST);
                }
            }
            ml_freeaddrinfo(res);
        } else {
            ESP_LOGW(TAG, "DNS resolve failed for %s", ML_STUN_FALLBACK_HOST);
            if (res) ml_freeaddrinfo(res);
        }
    }

    bool have_ipv4 = (ml->stun_primary_ip || ml->stun_fallback_ip);
    bool have_ipv6 = (memcmp(ml->stun_primary_ip6, zero16, 16) != 0);
    return (have_ipv4 || have_ipv6) ? ESP_OK : ESP_FAIL;
}

/* ============================================================================
 * Send Probe (hostname-based — legacy, resolves DNS each time)
 * ========================================================================== */

esp_err_t ml_stun_send_probe(microlink_t *ml, const char *server, uint16_t port) {
    /* Resolve STUN server — accept either IPv4 or IPv6 */
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (ml_getaddrinfo(server, port_str, &hints, &res) != 0 || !res) {
        ESP_LOGE(TAG, "DNS resolve failed for %s", server);
        return ESP_FAIL;
    }

    /* Use the appropriate socket for the address family.
     * IPv4: prefer disco_sock4 so NAT mapping matches DISCO socket.
     * IPv6: use dedicated stun_sock6 (no IPv6 DISCO socket). */
    int sock;
    uint8_t *txid;
    if (res->ai_family == AF_INET6) {
        if (ensure_stun_socket6(ml) != ESP_OK) {
            ml_freeaddrinfo(res);
            return ESP_FAIL;
        }
        sock = ml->stun_sock6;
        txid = txid_v6;
    } else {
        /* Use disco_sock4 for IPv4 STUN to match NAT mapping */
        if (ml->disco_sock4 >= 0) {
            sock = ml->disco_sock4;
        } else {
            if (ensure_stun_socket(ml) != ESP_OK) {
                ml_freeaddrinfo(res);
                return ESP_FAIL;
            }
            sock = ml->stun_sock;
        }
        txid = txid_v4;
    }

    /* Build Tailscale-compatible STUN request */
    uint8_t request[STUN_REQUEST_SIZE];
    size_t req_len = build_stun_request(request, txid);
    if (res->ai_family == AF_INET6)
        txid_v6_valid = true;
    else
        txid_v4_valid = true;

    /* Send */
    int n = ml_sendto(sock, request, req_len, 0,
                   res->ai_addr, res->ai_addrlen);
    ml_freeaddrinfo(res);

    if (n < 0) {
        ESP_LOGE(TAG, "STUN send failed: %d", errno);
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, "STUN probe sent to %s:%u (%d bytes)", server, port, (int)req_len);
    return ESP_OK;
}

/* ============================================================================
 * Send Probe (pre-resolved IP — no DNS in hot path)
 * ========================================================================== */

esp_err_t ml_stun_send_probe_to(microlink_t *ml, uint32_t server_ip, uint16_t port) {
    if (server_ip == 0) return ESP_ERR_INVALID_ARG;

    /* Use disco_sock4 for STUN probes so the NAT mapping (external IP:port)
     * applies to the same socket that receives incoming DISCO probes from peers.
     * Without this, STUN reports a port mapped to a separate socket, and peers
     * sending to that address reach the wrong socket (or get dropped by NAT). */
    int sock = ml->disco_sock4;
    if (sock < 0) {
        /* Fallback to dedicated STUN socket if disco not available */
        if (ensure_stun_socket(ml) != ESP_OK) return ESP_FAIL;
        sock = ml->stun_sock;
    }

    /* Build destination from pre-resolved IP (host byte order -> network) */
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(server_ip),
    };

    /* Build Tailscale-compatible STUN request */
    uint8_t request[STUN_REQUEST_SIZE];
    size_t req_len = build_stun_request(request, txid_v4);
    txid_v4_valid = true;

    /* Send */
    int n = ml_sendto(sock, request, req_len, 0,
                   (struct sockaddr *)&dest, sizeof(dest));
    if (n < 0) {
        ESP_LOGE(TAG, "STUN send failed: %d", errno);
        return ESP_FAIL;
    }

    char ip_str[16];
    microlink_ip_to_str(server_ip, ip_str);
    ESP_LOGD(TAG, "STUN probe sent to %s:%u (%d bytes)", ip_str, port, (int)req_len);
    return ESP_OK;
}

/* ============================================================================
 * Parse Response
 * ========================================================================== */

bool ml_stun_parse_response(const uint8_t *data, size_t len,
                              uint32_t *out_ip, uint16_t *out_port) {
    if (len < STUN_HEADER_SIZE) {
        ESP_LOGW(TAG, "STUN response too short: %d", (int)len);
        return false;
    }

    /* Verify message type: Binding Response (0x0101) */
    uint16_t msg_type = (data[0] << 8) | data[1];
    if (msg_type != STUN_BINDING_RESPONSE) {
        ESP_LOGW(TAG, "Not a STUN binding response: 0x%04x", msg_type);
        return false;
    }

    /* Verify magic cookie */
    uint32_t cookie = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (cookie != STUN_MAGIC_COOKIE) {
        ESP_LOGW(TAG, "Invalid STUN magic cookie");
        return false;
    }

    /* Check txid against IPv4 txid (IPv6 responses use separate parser) */
    /* Only accept a response to a request we actually have outstanding.
     * (Previously, once a probe succeeded and cleared txid_v4_valid, any
     * Binding Response from anyone was accepted and could rewrite our
     * advertised public endpoint.) */
    if (!txid_v4_valid || memcmp(data + 8, txid_v4, 12) != 0) {
        /* Could be an IPv6 response arriving on IPv4 queue — don't warn */
        ESP_LOGD(TAG, "STUN IPv4 txid mismatch (may be IPv6 response)");
        return false;
    }

    /* Parse message length */
    uint16_t msg_len = (data[2] << 8) | data[3];
    if (STUN_HEADER_SIZE + msg_len > len) {
        ESP_LOGW(TAG, "STUN message length exceeds packet");
        return false;
    }

    /* Iterate through attributes to find XOR-MAPPED-ADDRESS */
    bool found_ipv6_only = false;
    size_t offset = STUN_HEADER_SIZE;
    while (offset + 4 <= STUN_HEADER_SIZE + msg_len) {
        uint16_t attr_type = (data[offset] << 8) | data[offset + 1];
        uint16_t attr_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + attr_len > len) break;

        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS) {
            if (attr_len < 8) break;

            /* Family: 0x01=IPv4, 0x02=IPv6 */
            uint8_t family = data[offset + 1];
            if (family == 0x01) {
                /* IPv4: XOR port with top 16 bits of magic cookie */
                uint16_t xport = (data[offset + 2] << 8) | data[offset + 3];
                *out_port = xport ^ (STUN_MAGIC_COOKIE >> 16);

                /* XOR address with magic cookie */
                uint32_t xaddr = (data[offset + 4] << 24) |
                                 (data[offset + 5] << 16) |
                                 (data[offset + 6] << 8) |
                                  data[offset + 7];
                *out_ip = xaddr ^ STUN_MAGIC_COOKIE;

                char ip_str[16];
                microlink_ip_to_str(*out_ip, ip_str);
                ESP_LOGD(TAG, "STUN mapped: %s:%u", ip_str, *out_port);
                txid_v4_valid = false;
                return true;
            }
            if (family == 0x02) {
                found_ipv6_only = true;  /* Valid response, just not IPv4 */
            }
            offset += (attr_len + 3) & ~3;
            continue;
        }

        if (attr_type == STUN_ATTR_MAPPED_ADDRESS) {
            /* Fallback: non-XOR mapped address (RFC 3489 compat) */
            if (attr_len < 8) break;
            uint8_t family = data[offset + 1];
            if (family != 0x01) {
                offset += (attr_len + 3) & ~3;
                continue;
            }
            *out_port = (data[offset + 2] << 8) | data[offset + 3];
            *out_ip = (data[offset + 4] << 24) |
                      (data[offset + 5] << 16) |
                      (data[offset + 6] << 8) |
                       data[offset + 7];

            char ip_str[16];
            microlink_ip_to_str(*out_ip, ip_str);
            ESP_LOGD(TAG, "STUN mapped (legacy): %s:%u", ip_str, *out_port);
            txid_v4_valid = false;
            return true;
        }

        /* Advance to next attribute (4-byte aligned) */
        offset += (attr_len + 3) & ~3;
    }

    if (!found_ipv6_only) {
        ESP_LOGW(TAG, "STUN: no mapped address attribute found");
    }
    /* If found_ipv6_only, silently return false — IPv6 parser will handle it */
    return false;
}

/* ============================================================================
 * IPv6 STUN Support
 * ========================================================================== */

static esp_err_t ensure_stun_socket6(microlink_t *ml) {
    if (ml->stun_sock6 >= 0) return ESP_OK;

    ml->stun_sock6 = ml_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->stun_sock6 < 0) {
        ESP_LOGD(TAG, "Failed to create IPv6 STUN socket: %d (expected on IPv4-only)", errno);
        return ESP_FAIL;
    }

    /* Non-blocking */
    int flags = ml_fcntl(ml->stun_sock6, F_GETFL, 0);
    ml_fcntl(ml->stun_sock6, F_SETFL, flags | O_NONBLOCK);

    /* Bind to any port */
    struct sockaddr_in6 bind_addr = {
        .sin6_family = AF_INET6,
        .sin6_port = 0,
        .sin6_addr = IN6ADDR_ANY_INIT,
    };
    ml_bind(ml->stun_sock6, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

    return ESP_OK;
}

esp_err_t ml_stun_send_probe_ipv6(microlink_t *ml, const uint8_t *server_ip6, uint16_t port) {
    /* Check for zero address */
    static const uint8_t zero16[16] = {0};
    if (memcmp(server_ip6, zero16, 16) == 0) return ESP_ERR_INVALID_ARG;

    if (ensure_stun_socket6(ml) != ESP_OK) return ESP_FAIL;

    struct sockaddr_in6 dest = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port),
    };
    memcpy(&dest.sin6_addr, server_ip6, 16);

    /* Build Tailscale-compatible STUN request (separate txid from IPv4) */
    uint8_t request[STUN_REQUEST_SIZE];
    size_t req_len = build_stun_request(request, txid_v6);
    txid_v6_valid = true;

    int n = ml_sendto(ml->stun_sock6, request, req_len, 0,
                   (struct sockaddr *)&dest, sizeof(dest));
    if (n < 0) {
        /* ENETUNREACH/ENOTSUP expected on IPv4-only networks */
        if (errno == 118 || errno == 51 || errno == ENETUNREACH) {
            ESP_LOGD(TAG, "STUN IPv6 send: no IPv6 route (errno %d)", errno);
        } else {
            ESP_LOGE(TAG, "STUN IPv6 send failed: %d", errno);
        }
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, "STUN IPv6 probe sent (%d bytes)", (int)req_len);
    return ESP_OK;
}

bool ml_stun_parse_response_ipv6(const uint8_t *data, size_t len,
                                  uint8_t *out_ip6, uint16_t *out_port) {
    if (len < STUN_HEADER_SIZE) return false;

    /* Verify Binding Response */
    uint16_t msg_type = (data[0] << 8) | data[1];
    if (msg_type != STUN_BINDING_RESPONSE) return false;

    /* Verify magic cookie */
    uint32_t cookie = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (cookie != STUN_MAGIC_COOKIE) return false;

    /* Check txid against IPv6 txid first, then try IPv4 txid
     * (response may arrive on shared queue from either socket) */
    bool matched_v6 = (txid_v6_valid && memcmp(data + 8, txid_v6, 12) == 0);
    bool matched_v4 = (!matched_v6 && txid_v4_valid && memcmp(data + 8, txid_v4, 12) == 0);
    if (!matched_v6 && !matched_v4) return false;

    /* Use whichever txid matched for XOR decoding */
    const uint8_t *matched_txid = matched_v6 ? txid_v6 : txid_v4;

    uint16_t msg_len = (data[2] << 8) | data[3];
    if (STUN_HEADER_SIZE + msg_len > len) return false;

    size_t offset = STUN_HEADER_SIZE;
    while (offset + 4 <= STUN_HEADER_SIZE + msg_len) {
        uint16_t attr_type = (data[offset] << 8) | data[offset + 1];
        uint16_t attr_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + attr_len > len) break;

        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr_len >= 4) {
            uint8_t family = data[offset + 1];

            if (family == 0x02 && attr_len >= 20) {
                /* IPv6: XOR port with top 16 bits of magic cookie */
                uint16_t xport = (data[offset + 2] << 8) | data[offset + 3];
                *out_port = xport ^ (STUN_MAGIC_COOKIE >> 16);

                /* IPv6 XOR: first 4 bytes XOR magic cookie,
                 * remaining 12 bytes XOR transaction ID */
                uint8_t xor_bytes[16];
                xor_bytes[0] = 0x21; xor_bytes[1] = 0x12;
                xor_bytes[2] = 0xA4; xor_bytes[3] = 0x42;
                memcpy(xor_bytes + 4, matched_txid, 12);

                for (int i = 0; i < 16; i++) {
                    out_ip6[i] = data[offset + 4 + i] ^ xor_bytes[i];
                }

                ESP_LOGD(TAG, "STUN IPv6 mapped: port %u", *out_port);
                if (matched_v6) txid_v6_valid = false;
                else txid_v4_valid = false;
                return true;
            }

            if (family == 0x01 && attr_len >= 8) {
                /* Got IPv4 response on IPv6 socket (dual-stack) — skip */
                offset += (attr_len + 3) & ~3;
                continue;
            }
        }

        offset += (attr_len + 3) & ~3;
    }

    return false;
}
