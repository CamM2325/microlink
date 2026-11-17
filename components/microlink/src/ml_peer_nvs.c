/**
 * @file ml_peer_nvs.c
 * @brief Peer NVS Persistence - Cache peers across reboots
 *
 * Stores peer data (public key, disco key, VPN IP, endpoints) in NVS flash.
 * On boot, wg_mgr loads cached peers immediately so DISCO probing can start
 * before the control plane registration completes.
 *
 * Storage: single NVS blob containing a packed array of peer entries.
 * Supports up to ML_NVS_MAX_PEERS (64) with LRU eviction when full.
 * The entire table is written as one blob (~5.8KB max) for efficiency, so
 * writes are kept rare (flash wear): a save whose stored fields did not
 * change only bumps the LRU counter in RAM, and wg_mgr brackets each batch
 * of peer updates with ml_peer_nvs_batch_begin()/end() so a full netmap or
 * a stale-peer sweep costs one write, not one per peer.
 *
 * Reference: microlink v1 microlink_peer_registry.c
 */

#include "microlink_internal.h"
#include "wireguard-filter.h"   /* wg_endpoint_ip4_is_valid_underlay() */
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>

static const char *TAG = "ml_peer_nvs";

#define PEER_NVS_NAMESPACE  "ml_peers"
#define PEER_NVS_BLOB_KEY   "tbl"
#ifdef CONFIG_ML_NVS_MAX_PEERS
#define ML_NVS_MAX_PEERS    CONFIG_ML_NVS_MAX_PEERS
#else
#define ML_NVS_MAX_PEERS    64  /* Fallback default */
#endif

/* Compact peer storage (92 bytes per entry) */
typedef struct __attribute__((packed)) {
    uint32_t vpn_ip;                /* 4 bytes */
    uint8_t public_key[32];         /* 32 bytes */
    uint8_t disco_key[32];          /* 32 bytes */
    uint16_t derp_region;           /* 2 bytes */
    struct {
        uint32_t ip;                /* 4 bytes */
        uint16_t port;              /* 2 bytes */
    } __attribute__((packed)) endpoints[2]; /* 12 bytes */
    uint8_t endpoint_count;         /* 1 byte */
    char hostname_short[7];         /* 7 bytes (truncated) */
    uint16_t lru_counter;           /* 2 bytes — higher = more recently used */
} peer_nvs_entry_t;                 /* Total: 92 bytes */

/* In-memory table (loaded from NVS blob) */
typedef struct __attribute__((packed)) {
    uint16_t count;                 /* Number of valid entries */
    uint16_t lru_clock;             /* Monotonic LRU counter */
    peer_nvs_entry_t entries[ML_NVS_MAX_PEERS];
} peer_nvs_table_t;

static nvs_handle_t s_nvs = 0;
static bool s_initialized = false;
static peer_nvs_table_t *s_table = NULL;  /* PSRAM-allocated working copy */
static int s_batch_depth = 0;             /* >0: flushes are deferred */
static bool s_dirty = false;              /* stored fields changed since the last flush */

static void load_table(void) {
    if (!s_table) {
        s_table = ml_psram_calloc(1, sizeof(peer_nvs_table_t));
        if (!s_table) return;
    }

    size_t len = sizeof(peer_nvs_table_t);
    if (nvs_get_blob(s_nvs, PEER_NVS_BLOB_KEY, s_table, &len) != ESP_OK) {
        memset(s_table, 0, sizeof(peer_nvs_table_t));
        return;
    }
    /* Never trust stored lengths: clamp to what was actually read. */
    size_t max_entries = (len >= sizeof(uint16_t) * 2)
                         ? (len - sizeof(uint16_t) * 2) / sizeof(peer_nvs_entry_t) : 0;
    if (s_table->count > max_entries || s_table->count > ML_NVS_MAX_PEERS) {
        ESP_LOGW(TAG, "Peer cache count %u invalid (blob holds %u), resetting",
                 (unsigned)s_table->count, (unsigned)max_entries);
        memset(s_table, 0, sizeof(peer_nvs_table_t));
        return;
    }
    for (int i = 0; i < s_table->count; i++) {
        if (s_table->entries[i].endpoint_count > 2) {
            s_table->entries[i].endpoint_count = 2;
        }
    }
}

static esp_err_t write_table(void) {
    size_t blob_size = sizeof(uint16_t) * 2 +
                       s_table->count * sizeof(peer_nvs_entry_t);
    esp_err_t err = nvs_set_blob(s_nvs, PEER_NVS_BLOB_KEY, s_table, blob_size);
    if (err == ESP_OK) {
        err = nvs_commit(s_nvs);
    }
    if (err == ESP_OK) {
        s_dirty = false;
    } else {
        ESP_LOGW(TAG, "Peer cache write failed: %s", esp_err_to_name(err));
    }
    return err;
}

/* The table changed: write it now, or at the end of the current batch. */
static esp_err_t flush_table(void) {
    if (!s_table) return ESP_ERR_INVALID_STATE;
    s_dirty = true;
    if (s_batch_depth > 0) return ESP_OK;
    return write_table();
}

void ml_peer_nvs_batch_begin(void) {
    s_batch_depth++;
}

void ml_peer_nvs_batch_end(void) {
    if (s_batch_depth > 0) s_batch_depth--;
    if (s_batch_depth == 0 && s_dirty && s_initialized && s_table) {
        write_table();
    }
}

/* The 16-bit LRU clock would wrap after 65535 saves, after which fresh
 * entries would look oldest and be evicted first. Renumber the entries
 * 1..count in their current LRU order and restart the clock above them. */
static void lru_renormalise(void) {
    uint16_t n = s_table->count;
    uint16_t *rank = calloc(n ? n : 1, sizeof(uint16_t));
    for (int i = 0; i < n; i++) {
        uint16_t r = 1;
        for (int j = 0; j < n; j++) {
            uint16_t cj = s_table->entries[j].lru_counter;
            uint16_t ci = s_table->entries[i].lru_counter;
            if (cj < ci || (cj == ci && j < i)) r++;
        }
        if (rank) {
            rank[i] = r;
        } else {
            s_table->entries[i].lru_counter = 1;   /* no memory: order lost, not correctness */
        }
    }
    if (rank) {
        for (int i = 0; i < n; i++) s_table->entries[i].lru_counter = rank[i];
        free(rank);
    }
    s_table->lru_clock = n;
    ESP_LOGI(TAG, "LRU clock renormalised (%u entries)", (unsigned)n);
}

esp_err_t ml_peer_nvs_init(void) {
    if (s_initialized) return ESP_OK;

    esp_err_t err = nvs_open(PEER_NVS_NAMESPACE, NVS_READWRITE, &s_nvs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NVS open failed: %d (peer cache disabled)", err);
        return err;
    }

    s_initialized = true;
    load_table();

    ESP_LOGI(TAG, "Peer NVS initialized: %d cached peers (max %d)",
             s_table ? s_table->count : 0, ML_NVS_MAX_PEERS);

    return ESP_OK;
}

void ml_peer_nvs_deinit(void) {
    if (!s_initialized) return;
    nvs_close(s_nvs);
    s_initialized = false;
    if (s_table) {
        free(s_table);
        s_table = NULL;
    }
}

esp_err_t ml_peer_nvs_save(const ml_peer_t *peer) {
    if (!s_initialized || !peer || !s_table) return ESP_ERR_INVALID_STATE;

    /* Advance LRU clock */
    if (s_table->lru_clock >= UINT16_MAX - 1) {
        lru_renormalise();
    }
    s_table->lru_clock++;

    /* Build entry */
    peer_nvs_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    entry.vpn_ip = peer->vpn_ip;
    memcpy(entry.public_key, peer->public_key, 32);
    memcpy(entry.disco_key, peer->disco_key, 32);
    entry.derp_region = peer->derp_region;
    entry.lru_counter = s_table->lru_clock;

    /* Store up to 2 endpoints */
    int stored = 0;
    for (int i = 0; i < peer->endpoint_count && stored < 2; i++) {
        if (!peer->endpoints[i].is_ipv6 && peer->endpoints[i].ip != 0) {
            entry.endpoints[stored].ip = peer->endpoints[i].ip;
            entry.endpoints[stored].port = peer->endpoints[i].port;
            stored++;
        }
    }
    entry.endpoint_count = stored;

    /* Truncated hostname for display */
    strncpy(entry.hostname_short, peer->hostname, sizeof(entry.hostname_short) - 1);

    /* Find existing entry by VPN IP (update) or public key (re-keyed) */
    int slot = -1;
    for (int i = 0; i < s_table->count; i++) {
        if (s_table->entries[i].vpn_ip == peer->vpn_ip ||
            memcmp(s_table->entries[i].public_key, peer->public_key, 32) == 0) {
            slot = i;
            break;
        }
    }

    if (slot >= 0) {
        /* Nothing that is stored changed (endpoint changes beyond the first
         * two IPv4 ones, the hostname past 7 characters, online state...):
         * remember the use in RAM, don't rewrite the blob. */
        peer_nvs_entry_t cur = s_table->entries[slot];
        cur.lru_counter = entry.lru_counter;
        if (memcmp(&cur, &entry, sizeof(entry)) == 0) {
            s_table->entries[slot].lru_counter = entry.lru_counter;
            return ESP_OK;
        }
        /* Update existing entry */
        s_table->entries[slot] = entry;
    } else if (s_table->count < ML_NVS_MAX_PEERS) {
        /* Append new entry */
        slot = s_table->count;
        s_table->entries[slot] = entry;
        s_table->count++;
    } else {
        /* LRU eviction: find entry with lowest lru_counter */
        int lru_idx = 0;
        uint16_t min_lru = s_table->entries[0].lru_counter;
        for (int i = 1; i < s_table->count; i++) {
            if (s_table->entries[i].lru_counter < min_lru) {
                min_lru = s_table->entries[i].lru_counter;
                lru_idx = i;
            }
        }
        ESP_LOGI(TAG, "LRU evict: %s (slot=%d lru=%d)",
                 s_table->entries[lru_idx].hostname_short, lru_idx, min_lru);
        s_table->entries[lru_idx] = entry;
        slot = lru_idx;
    }

    esp_err_t err = flush_table();
    if (err == ESP_OK) {
        ESP_LOGD(TAG, "Saved peer %s (slot=%d/%d)",
                 entry.hostname_short, slot, s_table->count);
    }

    return err;
}

int ml_peer_nvs_load_all(ml_peer_t *peers, int max_peers) {
    if (!s_initialized || !peers || !s_table) return 0;
    if (s_table->count == 0) return 0;

    int loaded = 0;
    for (int i = 0; i < s_table->count && loaded < max_peers; i++) {
        peer_nvs_entry_t *entry = &s_table->entries[i];
        if (entry->vpn_ip == 0) continue;

        ml_peer_t *p = &peers[loaded];
        memset(p, 0, sizeof(ml_peer_t));

        p->vpn_ip = entry->vpn_ip;
        memcpy(p->public_key, entry->public_key, 32);
        memcpy(p->disco_key, entry->disco_key, 32);
        p->derp_region = entry->derp_region;
        p->active = true;
        p->wg_peer_index = -1;

        /* Restore hostname (truncated, ensure null-terminated) */
        memcpy(p->hostname, entry->hostname_short, sizeof(entry->hostname_short));
        p->hostname[sizeof(entry->hostname_short)] = '\0';

        /* Restore endpoints. Flash is not trusted: drop anything that is
         * not a usable underlay address (the same filter CallMeMaybe uses). */
        p->endpoint_count = 0;
        for (int j = 0; j < entry->endpoint_count && j < 2; j++) {
            if (entry->endpoints[j].port == 0 ||
                !wg_endpoint_ip4_is_valid_underlay(entry->endpoints[j].ip)) {
                continue;
            }
            int k = p->endpoint_count++;
            p->endpoints[k].ip = entry->endpoints[j].ip;
            p->endpoints[k].port = entry->endpoints[j].port;
            p->endpoints[k].is_ipv6 = false;
        }

        loaded++;

        char ip_str[16];
        microlink_ip_to_str(p->vpn_ip, ip_str);
        ESP_LOGI(TAG, "Loaded cached peer: %s (%s)", p->hostname, ip_str);
    }

    ESP_LOGI(TAG, "Loaded %d cached peers from NVS", loaded);
    return loaded;
}

/* Drop a peer from the cache (removed/revoked on the control plane), so it
 * is not re-installed from flash on the next boot. */
esp_err_t ml_peer_nvs_remove(const uint8_t *public_key) {
    if (!s_initialized || !s_table) return ESP_ERR_INVALID_STATE;
    for (int i = 0; i < s_table->count; i++) {
        if (memcmp(s_table->entries[i].public_key, public_key, 32) == 0) {
            s_table->entries[i] = s_table->entries[s_table->count - 1];
            memset(&s_table->entries[s_table->count - 1], 0, sizeof(peer_nvs_entry_t));
            s_table->count--;
            return flush_table();
        }
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t ml_peer_nvs_clear(void) {
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    esp_err_t err = nvs_erase_all(s_nvs);
    if (err == ESP_OK) {
        nvs_commit(s_nvs);
        if (s_table) memset(s_table, 0, sizeof(peer_nvs_table_t));
        ESP_LOGI(TAG, "Peer NVS cleared");
    }
    return err;
}
