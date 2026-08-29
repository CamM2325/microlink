/**
 * @file nacl_box.c
 * @brief Minimal NaCl crypto_box implementation for Tailscale challenge response
 *
 * Implements crypto_box using X25519 + HSalsa20 + XSalsa20-Poly1305
 * Based on TweetNaCl and DJB's reference implementations
 */

#include "nacl_box.h"
#include "x25519.h"
#include <string.h>
#include <stdbool.h>

/* Debug logging - set to 1 to enable */
#define NACL_BOX_DEBUG 0

#if NACL_BOX_DEBUG
#include "esp_log.h"
#include <stdio.h>
static const char *NACL_TAG = "nacl_box";
#define NACL_LOG_HEX(tag, data, len) do { \
    char hex[65]; \
    int hlen = (len) > 32 ? 32 : (len); \
    for (int i = 0; i < hlen; i++) sprintf(hex + i*2, "%02x", (data)[i]); \
    hex[hlen*2] = 0; \
    ESP_LOGI(NACL_TAG, "%s (%d bytes): %s%s", tag, (int)(len), hex, (len) > 32 ? "..." : ""); \
} while(0)
#else
#define NACL_LOG_HEX(tag, data, len)
#endif

/* ============================================================================
 * Salsa20 Core (different quarter round than ChaCha20)
 * ========================================================================== */

static uint32_t load32_le(const uint8_t *src) {
    return (uint32_t)src[0]
        | ((uint32_t)src[1] << 8)
        | ((uint32_t)src[2] << 16)
        | ((uint32_t)src[3] << 24);
}

static void store32_le(uint8_t *dst, uint32_t w) {
    dst[0] = (uint8_t)w;
    dst[1] = (uint8_t)(w >> 8);
    dst[2] = (uint8_t)(w >> 16);
    dst[3] = (uint8_t)(w >> 24);
}

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* Salsa20 core - 20 rounds */
static void salsa20_core(uint8_t *out, const uint8_t *in) {
    uint32_t x[16], y[16];
    int i;

    for (i = 0; i < 16; i++) {
        x[i] = y[i] = load32_le(in + 4 * i);
    }

    for (i = 0; i < 20; i += 2) {
        /* Odd round - columns */
        x[4]  ^= rotl32(x[0]  + x[12], 7);
        x[8]  ^= rotl32(x[4]  + x[0],  9);
        x[12] ^= rotl32(x[8]  + x[4],  13);
        x[0]  ^= rotl32(x[12] + x[8],  18);
        x[9]  ^= rotl32(x[5]  + x[1],  7);
        x[13] ^= rotl32(x[9]  + x[5],  9);
        x[1]  ^= rotl32(x[13] + x[9],  13);
        x[5]  ^= rotl32(x[1]  + x[13], 18);
        x[14] ^= rotl32(x[10] + x[6],  7);
        x[2]  ^= rotl32(x[14] + x[10], 9);
        x[6]  ^= rotl32(x[2]  + x[14], 13);
        x[10] ^= rotl32(x[6]  + x[2],  18);
        x[3]  ^= rotl32(x[15] + x[11], 7);
        x[7]  ^= rotl32(x[3]  + x[15], 9);
        x[11] ^= rotl32(x[7]  + x[3],  13);
        x[15] ^= rotl32(x[11] + x[7],  18);

        /* Even round - rows */
        x[1]  ^= rotl32(x[0]  + x[3],  7);
        x[2]  ^= rotl32(x[1]  + x[0],  9);
        x[3]  ^= rotl32(x[2]  + x[1],  13);
        x[0]  ^= rotl32(x[3]  + x[2],  18);
        x[6]  ^= rotl32(x[5]  + x[4],  7);
        x[7]  ^= rotl32(x[6]  + x[5],  9);
        x[4]  ^= rotl32(x[7]  + x[6],  13);
        x[5]  ^= rotl32(x[4]  + x[7],  18);
        x[11] ^= rotl32(x[10] + x[9],  7);
        x[8]  ^= rotl32(x[11] + x[10], 9);
        x[9]  ^= rotl32(x[8]  + x[11], 13);
        x[10] ^= rotl32(x[9]  + x[8],  18);
        x[12] ^= rotl32(x[15] + x[14], 7);
        x[13] ^= rotl32(x[12] + x[15], 9);
        x[14] ^= rotl32(x[13] + x[12], 13);
        x[15] ^= rotl32(x[14] + x[13], 18);
    }

    for (i = 0; i < 16; i++) {
        store32_le(out + 4 * i, x[i] + y[i]);
    }
}

/* HSalsa20 - derives subkey from key and 16-byte nonce */
static void hsalsa20(uint8_t *out, const uint8_t *nonce, const uint8_t *key) {
    uint32_t x[16];
    int i;

    /* sigma = "expand 32-byte k" */
    static const uint8_t sigma[16] = "expand 32-byte k";

    x[0]  = load32_le(sigma);
    x[5]  = load32_le(sigma + 4);
    x[10] = load32_le(sigma + 8);
    x[15] = load32_le(sigma + 12);
    x[1]  = load32_le(key);
    x[2]  = load32_le(key + 4);
    x[3]  = load32_le(key + 8);
    x[4]  = load32_le(key + 12);
    x[11] = load32_le(key + 16);
    x[12] = load32_le(key + 20);
    x[13] = load32_le(key + 24);
    x[14] = load32_le(key + 28);
    x[6]  = load32_le(nonce);
    x[7]  = load32_le(nonce + 4);
    x[8]  = load32_le(nonce + 8);
    x[9]  = load32_le(nonce + 12);

    for (i = 0; i < 20; i += 2) {
        /* Odd round - columns */
        x[4]  ^= rotl32(x[0]  + x[12], 7);
        x[8]  ^= rotl32(x[4]  + x[0],  9);
        x[12] ^= rotl32(x[8]  + x[4],  13);
        x[0]  ^= rotl32(x[12] + x[8],  18);
        x[9]  ^= rotl32(x[5]  + x[1],  7);
        x[13] ^= rotl32(x[9]  + x[5],  9);
        x[1]  ^= rotl32(x[13] + x[9],  13);
        x[5]  ^= rotl32(x[1]  + x[13], 18);
        x[14] ^= rotl32(x[10] + x[6],  7);
        x[2]  ^= rotl32(x[14] + x[10], 9);
        x[6]  ^= rotl32(x[2]  + x[14], 13);
        x[10] ^= rotl32(x[6]  + x[2],  18);
        x[3]  ^= rotl32(x[15] + x[11], 7);
        x[7]  ^= rotl32(x[3]  + x[15], 9);
        x[11] ^= rotl32(x[7]  + x[3],  13);
        x[15] ^= rotl32(x[11] + x[7],  18);

        /* Even round - rows */
        x[1]  ^= rotl32(x[0]  + x[3],  7);
        x[2]  ^= rotl32(x[1]  + x[0],  9);
        x[3]  ^= rotl32(x[2]  + x[1],  13);
        x[0]  ^= rotl32(x[3]  + x[2],  18);
        x[6]  ^= rotl32(x[5]  + x[4],  7);
        x[7]  ^= rotl32(x[6]  + x[5],  9);
        x[4]  ^= rotl32(x[7]  + x[6],  13);
        x[5]  ^= rotl32(x[4]  + x[7],  18);
        x[11] ^= rotl32(x[10] + x[9],  7);
        x[8]  ^= rotl32(x[11] + x[10], 9);
        x[9]  ^= rotl32(x[8]  + x[11], 13);
        x[10] ^= rotl32(x[9]  + x[8],  18);
        x[12] ^= rotl32(x[15] + x[14], 7);
        x[13] ^= rotl32(x[12] + x[15], 9);
        x[14] ^= rotl32(x[13] + x[12], 13);
        x[15] ^= rotl32(x[14] + x[13], 18);
    }

    /* Extract subkey (no final addition for HSalsa20) */
    store32_le(out,      x[0]);
    store32_le(out + 4,  x[5]);
    store32_le(out + 8,  x[10]);
    store32_le(out + 12, x[15]);
    store32_le(out + 16, x[6]);
    store32_le(out + 20, x[7]);
    store32_le(out + 24, x[8]);
    store32_le(out + 28, x[9]);
}

/* XSalsa20 stream cipher - uses HSalsa20 for subkey derivation */
static void xsalsa20(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t *nonce, const uint8_t *key) {
    uint8_t subkey[32];
    uint8_t block[64];
    uint8_t state[64];
    size_t i;
    uint64_t ctr = 0;

    /* Derive subkey using first 16 bytes of nonce */
    hsalsa20(subkey, nonce, key);

    /* sigma = "expand 32-byte k" */
    static const uint8_t sigma[16] = "expand 32-byte k";

    /* Set up state for Salsa20 with remaining 8 bytes of nonce
     * Salsa20 state layout (16 x 32-bit words):
     *   [0]  = sigma[0:4]    [1]  = key[0:4]     [2]  = key[4:8]     [3]  = key[8:12]
     *   [4]  = key[12:16]    [5]  = sigma[4:8]   [6]  = nonce[0:4]   [7]  = nonce[4:8]
     *   [8]  = counter_lo    [9]  = counter_hi   [10] = sigma[8:12]  [11] = key[16:20]
     *   [12] = key[20:24]    [13] = key[24:28]   [14] = key[28:32]   [15] = sigma[12:16]
     */
    memcpy(state + 0, sigma, 4);           /* word 0: sigma[0:4] */
    memcpy(state + 4, subkey, 4);          /* word 1: key[0:4] */
    memcpy(state + 8, subkey + 4, 4);      /* word 2: key[4:8] */
    memcpy(state + 12, subkey + 8, 4);     /* word 3: key[8:12] */
    memcpy(state + 16, subkey + 12, 4);    /* word 4: key[12:16] */
    memcpy(state + 20, sigma + 4, 4);      /* word 5: sigma[4:8] */
    memcpy(state + 24, nonce + 16, 4);     /* word 6: nonce[16:20] */
    memcpy(state + 28, nonce + 20, 4);     /* word 7: nonce[20:24] */
    memset(state + 32, 0, 8);              /* words 8-9: counter = 0 */
    memcpy(state + 40, sigma + 8, 4);      /* word 10: sigma[8:12] */
    memcpy(state + 44, subkey + 16, 4);    /* word 11: key[16:20] */
    memcpy(state + 48, subkey + 20, 4);    /* word 12: key[20:24] */
    memcpy(state + 52, subkey + 24, 4);    /* word 13: key[24:28] */
    memcpy(state + 56, subkey + 28, 4);    /* word 14: key[28:32] */
    memcpy(state + 60, sigma + 12, 4);     /* word 15: sigma[12:16] */

    while (len > 0) {
        /* Set counter in state */
        store32_le(state + 32, (uint32_t)ctr);
        store32_le(state + 36, (uint32_t)(ctr >> 32));

        salsa20_core(block, state);

        size_t chunk = (len < 64) ? len : 64;
        for (i = 0; i < chunk; i++) {
            out[i] = in[i] ^ block[i];
        }

        len -= chunk;
        in += chunk;
        out += chunk;
        ctr++;
    }

    /* Clear sensitive data */
    memset(subkey, 0, sizeof(subkey));
    memset(block, 0, sizeof(block));
    memset(state, 0, sizeof(state));
}

/* ============================================================================
 * Poly1305 MAC (radix 2^26 implementation)
 * ========================================================================== */

/*
 * Poly1305 using radix-2^26 representation for efficient computation.
 * The 130-bit accumulator h and 128-bit key r are stored in 5 x 26-bit limbs.
 * Reference: https://cr.yp.to/mac/poly1305-20050329.pdf
 */

typedef struct {
    uint32_t r[5];      /* r in radix-2^26 (clamped key) */
    uint32_t h[5];      /* accumulator in radix-2^26 */
    uint32_t pad[4];    /* pad = key[16..31] in 32-bit words */
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t *key) {
    uint32_t t0, t1, t2, t3;

    /* Load first 16 bytes of key into 32-bit words */
    t0 = load32_le(key + 0);
    t1 = load32_le(key + 4);
    t2 = load32_le(key + 8);
    t3 = load32_le(key + 12);

    /* Convert to radix-2^26 with clamping
     * Poly1305 requires certain bits to be 0:
     * - Top 4 bits of r[1], r[2], r[3], r[4] must be 0
     * - Bottom 2 bits of r[1], r[2], r[3] must be 0
     */
    st->r[0] = t0 & 0x3ffffff;
    st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    st->r[4] = (t3 >> 8) & 0x00fffff;

    /* Initialize accumulator to 0 */
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;

    /* Load pad (second 16 bytes of key) */
    st->pad[0] = load32_le(key + 16);
    st->pad[1] = load32_le(key + 20);
    st->pad[2] = load32_le(key + 24);
    st->pad[3] = load32_le(key + 28);
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *m, size_t len, int final) {
    uint32_t hibit = final ? 0 : (1 << 24);  /* 2^128 bit for non-final blocks */
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    while (len >= 16) {
        /* Add message block to accumulator (convert to radix-2^26) */
        h0 += load32_le(m + 0) & 0x3ffffff;
        h1 += (load32_le(m + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m + 12) >> 8) | hibit;

        /* h = h * r mod 2^130-5 (schoolbook multiplication with modular reduction) */
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        /* Partial carry propagation */
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        m += 16;
        len -= 16;
    }

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_finish(poly1305_state *st, uint8_t *mac) {
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c, g0, g1, g2, g3, g4, mask;
    uint64_t f;

    /* Fully carry h */
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    /* Compute h - p = h + -p = h + (2^130 - 5 - 2^130) = h - (2^130 - 5) */
    /* We add 5 and check for overflow to determine if h >= p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1 << 26);

    /* If h >= p, use h - p (which is g), else use h
     * g4 will have bit 31 set if there was no overflow (h < p) */
    mask = (g4 >> 31) - 1;  /* 0xffffffff if h >= p, 0x00000000 if h < p */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* Convert from radix-2^26 to radix-2^32 */
    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    /* mac = (h + pad) mod 2^128 */
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32_le(mac, h0);
    store32_le(mac + 4, h1);
    store32_le(mac + 8, h2);
    store32_le(mac + 12, h3);
}

static void poly1305(uint8_t *mac, const uint8_t *m, size_t len, const uint8_t *key) {
    poly1305_state st;
    uint8_t final_block[16];

    poly1305_init(&st, key);

    /* Process full 16-byte blocks */
    if (len >= 16) {
        size_t full_blocks = len & ~15UL;
        poly1305_blocks(&st, m, full_blocks, 0);
        m += full_blocks;
        len -= full_blocks;
    }

    /* Process final partial block with padding */
    if (len > 0) {
        memset(final_block, 0, 16);
        memcpy(final_block, m, len);
        final_block[len] = 1;  /* 10* padding */
        poly1305_blocks(&st, final_block, 16, 1);
    }

    poly1305_finish(&st, mac);

    /* Clear sensitive state */
    memset(&st, 0, sizeof(st));
}

/* ============================================================================
 * NaCl Box (secretbox with X25519 key agreement)
 * ========================================================================== */

/* XSalsa20-Poly1305 secretbox
 *
 * NaCl secretbox layout:
 * - Generate 64-byte block 0 from XSalsa20
 * - Bytes 0-31 of block 0: Poly1305 one-time key
 * - Bytes 32-63 of block 0: First 32 bytes of encryption keystream
 * - Block 1 onwards: Continue encryption keystream
 */
static int secretbox(uint8_t *ciphertext,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *nonce,
                     const uint8_t *key) {
    uint8_t subkey[32];
    uint8_t block0[64];
    uint8_t state[64];
    static const uint8_t sigma[16] = "expand 32-byte k";

    NACL_LOG_HEX("secretbox key", key, 32);
    NACL_LOG_HEX("secretbox nonce", nonce, 24);
    NACL_LOG_HEX("secretbox plaintext", plaintext, plaintext_len);

    /* Derive subkey using first 16 bytes of nonce via HSalsa20 */
    hsalsa20(subkey, nonce, key);
    NACL_LOG_HEX("secretbox subkey (HSalsa20)", subkey, 32);

    /* Build Salsa20 state for XSalsa20 (uses subkey + last 8 bytes of nonce)
     * Salsa20 state layout (16 x 32-bit words):
     *   [0]  = sigma[0:4]    [1]  = key[0:4]     [2]  = key[4:8]     [3]  = key[8:12]
     *   [4]  = key[12:16]    [5]  = sigma[4:8]   [6]  = nonce[0:4]   [7]  = nonce[4:8]
     *   [8]  = counter_lo    [9]  = counter_hi   [10] = sigma[8:12]  [11] = key[16:20]
     *   [12] = key[20:24]    [13] = key[24:28]   [14] = key[28:32]   [15] = sigma[12:16]
     */
    memcpy(state + 0, sigma, 4);           /* word 0: sigma[0:4] */
    memcpy(state + 4, subkey, 4);          /* word 1: key[0:4] */
    memcpy(state + 8, subkey + 4, 4);      /* word 2: key[4:8] */
    memcpy(state + 12, subkey + 8, 4);     /* word 3: key[8:12] */
    memcpy(state + 16, subkey + 12, 4);    /* word 4: key[12:16] */
    memcpy(state + 20, sigma + 4, 4);      /* word 5: sigma[4:8] */
    memcpy(state + 24, nonce + 16, 4);     /* word 6: nonce[16:20] (last 8 bytes) */
    memcpy(state + 28, nonce + 20, 4);     /* word 7: nonce[20:24] */
    store32_le(state + 32, 0);             /* word 8: counter_lo = 0 */
    store32_le(state + 36, 0);             /* word 9: counter_hi = 0 */
    memcpy(state + 40, sigma + 8, 4);      /* word 10: sigma[8:12] */
    memcpy(state + 44, subkey + 16, 4);    /* word 11: key[16:20] */
    memcpy(state + 48, subkey + 20, 4);    /* word 12: key[20:24] */
    memcpy(state + 52, subkey + 24, 4);    /* word 13: key[24:28] */
    memcpy(state + 56, subkey + 28, 4);    /* word 14: key[28:32] */
    memcpy(state + 60, sigma + 12, 4);     /* word 15: sigma[12:16] */

    /* Generate block 0: first 32 bytes = Poly1305 key, next 32 = encryption start */
    salsa20_core(block0, state);
    NACL_LOG_HEX("block0 (Poly1305 key + keystream)", block0, 64);

    /* Poly1305 key is first 32 bytes of block 0 */
    uint8_t poly_key[32];
    memcpy(poly_key, block0, 32);
    NACL_LOG_HEX("Poly1305 key (block0[0:32])", poly_key, 32);

    /* Encrypt plaintext starting from byte 32 of block 0 */
    uint8_t *out = ciphertext + NACL_BOX_MACBYTES;  /* Leave room for MAC */
    const uint8_t *in = plaintext;
    size_t len = plaintext_len;

    /* Use remaining 32 bytes of block 0 first */
    size_t block0_avail = 32;  /* bytes 32-63 of block 0 */
    size_t block0_use = (len < block0_avail) ? len : block0_avail;
    for (size_t i = 0; i < block0_use; i++) {
        out[i] = in[i] ^ block0[32 + i];
    }
    out += block0_use;
    in += block0_use;
    len -= block0_use;

    /* Continue with block 1 onwards if needed */
    uint64_t ctr = 1;
    while (len > 0) {
        uint8_t block[64];
        store32_le(state + 32, (uint32_t)ctr);
        store32_le(state + 36, (uint32_t)(ctr >> 32));
        salsa20_core(block, state);

        size_t chunk = (len < 64) ? len : 64;
        for (size_t i = 0; i < chunk; i++) {
            out[i] = in[i] ^ block[i];
        }

        len -= chunk;
        in += chunk;
        out += chunk;
        ctr++;
    }

    NACL_LOG_HEX("ciphertext (after XOR)", ciphertext + NACL_BOX_MACBYTES, plaintext_len);

    /* Compute MAC over ciphertext */
    poly1305(ciphertext, ciphertext + NACL_BOX_MACBYTES, plaintext_len, poly_key);
    NACL_LOG_HEX("Poly1305 MAC", ciphertext, NACL_BOX_MACBYTES);

    /* Clear sensitive data */
    memset(poly_key, 0, sizeof(poly_key));
    memset(subkey, 0, sizeof(subkey));
    memset(block0, 0, sizeof(block0));
    memset(state, 0, sizeof(state));

    return 0;
}

int nacl_box_beforenm(uint8_t *shared_key,
                      const uint8_t *recipient_pk,
                      const uint8_t *sender_sk) {
    uint8_t scalarmult_result[32];
    static const uint8_t zero_nonce[16] = {0};

    NACL_LOG_HEX("beforenm recipient_pk", recipient_pk, 32);
    NACL_LOG_HEX("beforenm sender_sk", sender_sk, 32);

    /* X25519 shared secret
     * The x25519() function with clamp=1 will properly clamp the scalar (private key)
     * by clearing the 3 lowest bits, clearing the highest bit, and setting bit 254.
     * The public key should NOT be modified - RFC 7748's bit clearing applies to the
     * scalar, not the u-coordinate (public key).
     *
     * NaCl uses clamped scalars for key agreement, so we pass clamp=1.
     */
    x25519(scalarmult_result, sender_sk, recipient_pk, 1);
    NACL_LOG_HEX("X25519 shared secret", scalarmult_result, 32);

    /* HSalsa20 to derive symmetric key */
    hsalsa20(shared_key, zero_nonce, scalarmult_result);
    NACL_LOG_HEX("HSalsa20 derived key", shared_key, 32);

    memset(scalarmult_result, 0, sizeof(scalarmult_result));
    return 0;
}

/* ---------------------------------------------------------------------------
 * Shared-key cache
 *
 * Keyed on the peer public key; our secret key never changes at runtime, so a
 * hit avoids the X25519 that would otherwise run on every DISCO packet.
 * Entries are replaced round-robin - a tailnet has far fewer simultaneously
 * active peers than slots, and a miss costs exactly what the old path did.
 * ------------------------------------------------------------------------- */

#define NACL_SHARED_CACHE_SLOTS 24

static struct {
    uint8_t peer_pk[32];
    uint8_t shared_key[32];
    bool    valid;
} s_shared_cache[NACL_SHARED_CACHE_SLOTS];

static int s_shared_cache_next;

int nacl_box_shared_get(uint8_t *shared_key,
                        const uint8_t *peer_pk,
                        const uint8_t *our_sk) {
    for (int i = 0; i < NACL_SHARED_CACHE_SLOTS; i++) {
        if (s_shared_cache[i].valid &&
            memcmp(s_shared_cache[i].peer_pk, peer_pk, 32) == 0) {
            memcpy(shared_key, s_shared_cache[i].shared_key, 32);
            return 0;
        }
    }

    int ret = nacl_box_beforenm(shared_key, peer_pk, our_sk);
    if (ret != 0) return ret;

    int slot = s_shared_cache_next;
    s_shared_cache_next = (s_shared_cache_next + 1) % NACL_SHARED_CACHE_SLOTS;
    memcpy(s_shared_cache[slot].peer_pk, peer_pk, 32);
    memcpy(s_shared_cache[slot].shared_key, shared_key, 32);
    s_shared_cache[slot].valid = true;
    return 0;
}

int nacl_box_afternm(uint8_t *ciphertext,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *nonce,
                     const uint8_t *shared_key) {
    return secretbox(ciphertext, plaintext, plaintext_len, nonce, shared_key);
}

int nacl_box(uint8_t *ciphertext,
             const uint8_t *plaintext, size_t plaintext_len,
             const uint8_t *nonce,
             const uint8_t *recipient_pk,
             const uint8_t *sender_sk) {
    uint8_t shared_key[32];

    nacl_box_beforenm(shared_key, recipient_pk, sender_sk);
    int ret = nacl_box_afternm(ciphertext, plaintext, plaintext_len, nonce, shared_key);

    memset(shared_key, 0, sizeof(shared_key));
    return ret;
}

/* Constant-time comparison */
static int verify16(const uint8_t *x, const uint8_t *y) {
    uint32_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= x[i] ^ y[i];
    }
    return (1 & ((diff - 1) >> 8)) - 1;  /* 0 if equal, -1 if different */
}

/* XSalsa20-Poly1305 secretbox_open (decryption)
 *
 * Verifies MAC, then decrypts.
 * Returns 0 on success, -1 on failure (MAC verification failed)
 */
static int secretbox_open(uint8_t *plaintext,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *nonce,
                          const uint8_t *key) {
    uint8_t subkey[32];
    uint8_t block0[64];
    uint8_t state[64];
    uint8_t computed_mac[16];
    static const uint8_t sigma[16] = "expand 32-byte k";

    if (ciphertext_len < NACL_BOX_MACBYTES) {
        return -1;
    }

    size_t plaintext_len = ciphertext_len - NACL_BOX_MACBYTES;

    NACL_LOG_HEX("secretbox_open key", key, 32);
    NACL_LOG_HEX("secretbox_open nonce", nonce, 24);
    NACL_LOG_HEX("secretbox_open ciphertext", ciphertext, ciphertext_len);

    /* Derive subkey using first 16 bytes of nonce via HSalsa20 */
    hsalsa20(subkey, nonce, key);

    /* Build Salsa20 state for XSalsa20 */
    memcpy(state + 0, sigma, 4);
    memcpy(state + 4, subkey, 4);
    memcpy(state + 8, subkey + 4, 4);
    memcpy(state + 12, subkey + 8, 4);
    memcpy(state + 16, subkey + 12, 4);
    memcpy(state + 20, sigma + 4, 4);
    memcpy(state + 24, nonce + 16, 4);
    memcpy(state + 28, nonce + 20, 4);
    store32_le(state + 32, 0);
    store32_le(state + 36, 0);
    memcpy(state + 40, sigma + 8, 4);
    memcpy(state + 44, subkey + 16, 4);
    memcpy(state + 48, subkey + 20, 4);
    memcpy(state + 52, subkey + 24, 4);
    memcpy(state + 56, subkey + 28, 4);
    memcpy(state + 60, sigma + 12, 4);

    /* Generate block 0: first 32 bytes = Poly1305 key */
    salsa20_core(block0, state);

    uint8_t poly_key[32];
    memcpy(poly_key, block0, 32);

    /* Verify MAC (ciphertext starts after MAC) */
    poly1305(computed_mac, ciphertext + NACL_BOX_MACBYTES, plaintext_len, poly_key);
    NACL_LOG_HEX("computed MAC", computed_mac, 16);
    NACL_LOG_HEX("expected MAC", ciphertext, 16);

    if (verify16(computed_mac, ciphertext) != 0) {
        NACL_LOG_HEX("MAC verification FAILED", computed_mac, 16);
        memset(poly_key, 0, sizeof(poly_key));
        memset(subkey, 0, sizeof(subkey));
        memset(block0, 0, sizeof(block0));
        memset(state, 0, sizeof(state));
        return -1;
    }

    /* Decrypt ciphertext (same as encrypt - XOR with keystream) */
    const uint8_t *in = ciphertext + NACL_BOX_MACBYTES;
    uint8_t *out = plaintext;
    size_t len = plaintext_len;

    /* Use remaining 32 bytes of block 0 first */
    size_t block0_avail = 32;
    size_t block0_use = (len < block0_avail) ? len : block0_avail;
    for (size_t i = 0; i < block0_use; i++) {
        out[i] = in[i] ^ block0[32 + i];
    }
    out += block0_use;
    in += block0_use;
    len -= block0_use;

    /* Continue with block 1 onwards if needed */
    uint64_t ctr = 1;
    while (len > 0) {
        uint8_t block[64];
        store32_le(state + 32, (uint32_t)ctr);
        store32_le(state + 36, (uint32_t)(ctr >> 32));
        salsa20_core(block, state);

        size_t chunk = (len < 64) ? len : 64;
        for (size_t i = 0; i < chunk; i++) {
            out[i] = in[i] ^ block[i];
        }

        len -= chunk;
        in += chunk;
        out += chunk;
        ctr++;
    }

    NACL_LOG_HEX("decrypted plaintext", plaintext, plaintext_len);

    /* Clear sensitive data */
    memset(poly_key, 0, sizeof(poly_key));
    memset(subkey, 0, sizeof(subkey));
    memset(block0, 0, sizeof(block0));
    memset(state, 0, sizeof(state));

    return 0;
}

int nacl_box_open_afternm(uint8_t *plaintext,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *nonce,
                          const uint8_t *shared_key) {
    return secretbox_open(plaintext, ciphertext, ciphertext_len, nonce, shared_key);
}

int nacl_box_open(uint8_t *plaintext,
                  const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *nonce,
                  const uint8_t *sender_pk,
                  const uint8_t *recipient_sk) {
    uint8_t shared_key[32];

    nacl_box_beforenm(shared_key, sender_pk, recipient_sk);
    int ret = nacl_box_open_afternm(plaintext, ciphertext, ciphertext_len, nonce, shared_key);

    memset(shared_key, 0, sizeof(shared_key));
    return ret;
}
