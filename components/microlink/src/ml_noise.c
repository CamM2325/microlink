/**
 * @file ml_noise.c
 * @brief Noise IK Protocol Implementation
 *
 * Implements Noise_IK_25519_ChaChaPoly_BLAKE2s handshake
 * for Tailscale control plane authentication.
 *
 * Handshake:
 *   -> e, es, s, ss    (msg1: client -> server)
 *   <- e, ee, se       (msg2: server -> client)
 *   Derives transport keys for encrypted HTTP/2 framing.
 *
 * Reference: tailscale/control/controlclient/noise.go
 *            noiseprotocol.org/noise.html
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "ml_noise_aead.h"
#include <string.h>

static const char *TAG = "ml_noise";

/* X25519 from x25519.h */
#include "x25519.h"

/* BLAKE2s from wireguard-lwip (RFC 7693 reference implementation) */
#include "blake2s.h"

/* Tailscale control plane server public key */
static const uint8_t TAILSCALE_SERVER_PUBLIC_KEY[32] = {
    0x7d, 0x27, 0x92, 0xf9, 0xc9, 0x8d, 0x75, 0x3d,
    0x20, 0x42, 0x47, 0x15, 0x36, 0x80, 0x19, 0x49,
    0x10, 0x4c, 0x24, 0x7f, 0x95, 0xea, 0xc7, 0x70,
    0xf8, 0xfb, 0x32, 0x15, 0x95, 0xe2, 0x17, 0x3b
};

/* Noise protocol name for hash init */
static const char NOISE_PROTOCOL_NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/* ============================================================================
 * BLAKE2s Hash + HMAC-BLAKE2s
 *
 * Uses the RFC 7693 BLAKE2s implementation from wireguard-lwip.
 * Tailscale's Noise handshake requires BLAKE2s-256 — NOT SHA-256.
 * Reference: tailscale/control/controlbase/handshake.go
 * ========================================================================== */

/* BLAKE2s-256: H(data) */
static void noise_hash(uint8_t out[32], const uint8_t *data, size_t len) {
    blake2s(out, 32, NULL, 0, data, len);
}

/* HMAC-BLAKE2s-256: HMAC(key, data)
 * Standard HMAC construction (RFC 2104) using BLAKE2s as the hash.
 * Block size = 64 bytes (BLAKE2S_BLOCK_SIZE), output size = 32 bytes. */
static void hmac_blake2s(uint8_t out[32],
                          const uint8_t *key, size_t key_len,
                          const uint8_t *data, size_t data_len) {
    uint8_t ipad[BLAKE2S_BLOCK_SIZE];
    uint8_t opad[BLAKE2S_BLOCK_SIZE];
    uint8_t key_block[BLAKE2S_BLOCK_SIZE];
    uint8_t inner_hash[32];

    /* If key > block size, hash it first */
    if (key_len > BLAKE2S_BLOCK_SIZE) {
        noise_hash(key_block, key, key_len);
        key_len = 32;
    } else {
        memcpy(key_block, key, key_len);
    }
    /* Pad key to block size with zeros */
    if (key_len < BLAKE2S_BLOCK_SIZE) {
        memset(key_block + key_len, 0, BLAKE2S_BLOCK_SIZE - key_len);
    }

    /* Inner: BLAKE2s((key XOR ipad) || data) */
    for (int i = 0; i < BLAKE2S_BLOCK_SIZE; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    blake2s_ctx ctx;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, ipad, BLAKE2S_BLOCK_SIZE);
    blake2s_update(&ctx, data, data_len);
    blake2s_final(&ctx, inner_hash);

    /* Outer: BLAKE2s((key XOR opad) || inner_hash) */
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, opad, BLAKE2S_BLOCK_SIZE);
    blake2s_update(&ctx, inner_hash, 32);
    blake2s_final(&ctx, out);

    memset(key_block, 0, sizeof(key_block));
    memset(inner_hash, 0, sizeof(inner_hash));
}

/* ============================================================================
 * Noise Primitives
 * ========================================================================== */

/* HKDF-BLAKE2s: Extract-then-expand with HMAC-BLAKE2s (RFC 5869) */
static void noise_hkdf(const uint8_t *ck, const uint8_t *input, size_t input_len,
                         uint8_t *out1, uint8_t *out2, uint8_t *out3) {
    /* Extract: temp_key = HMAC-BLAKE2s(ck, input) */
    uint8_t temp_key[32];
    hmac_blake2s(temp_key, ck, 32, input, input_len);

    /* Expand: out1 = HMAC(temp_key, 0x01) */
    uint8_t one = 0x01;
    hmac_blake2s(out1, temp_key, 32, &one, 1);

    if (out2) {
        /* out2 = HMAC(temp_key, out1 || 0x02) */
        uint8_t buf[33];
        memcpy(buf, out1, 32);
        buf[32] = 0x02;
        hmac_blake2s(out2, temp_key, 32, buf, 33);

        if (out3) {
            /* out3 = HMAC(temp_key, out2 || 0x03) */
            memcpy(buf, out2, 32);
            buf[32] = 0x03;
            hmac_blake2s(out3, temp_key, 32, buf, 33);
        }
    }

    memset(temp_key, 0, sizeof(temp_key));
}

/* Mix hash: h = BLAKE2s(h || data) using incremental API */
static void noise_mix_hash(uint8_t h[32], const uint8_t *data, size_t data_len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, h, 32);
    blake2s_update(&ctx, data, data_len);
    blake2s_final(&ctx, h);
}

/* Mix key: update chaining key and derive key */
static void noise_mix_key(uint8_t ck[32], uint8_t k[32], const uint8_t *dh_output) {
    noise_hkdf(ck, dh_output, 32, ck, k, NULL);
}

/* ============================================================================
 * ChaCha20-Poly1305 AEAD (Noise uses 64-bit nonce, padded to 96-bit)
 * ========================================================================== */

/* noise_aead_encrypt() / noise_aead_decrypt() live in ml_noise_aead.h. */

/* ============================================================================
 * Noise IK Handshake
 * ========================================================================== */

void ml_noise_init(ml_noise_state_t *state,
                    const uint8_t *local_private, const uint8_t *local_public,
                    const uint8_t *remote_public) {
    memset(state, 0, sizeof(*state));

    /* Copy keys */
    memcpy(state->local_static_private, local_private, 32);
    memcpy(state->local_static_public, local_public, 32);

    if (remote_public) {
        memcpy(state->remote_static_public, remote_public, 32);
    } else {
        memcpy(state->remote_static_public, TAILSCALE_SERVER_PUBLIC_KEY, 32);
    }

    /* Initialize handshake hash: h = BLAKE2s(protocol_name) */
    noise_hash(state->h, (const uint8_t *)NOISE_PROTOCOL_NAME,
               strlen(NOISE_PROTOCOL_NAME));

    /* ck = h (for Noise IK) */
    memcpy(state->ck, state->h, 32);

    /* Mix in Tailscale prologue */
    char prologue[64];
    int prologue_len = snprintf(prologue, sizeof(prologue),
                                "Tailscale Control Protocol v%d",
                                ML_CTRL_PROTOCOL_VER);
    noise_mix_hash(state->h, (const uint8_t *)prologue, prologue_len);

    /* IK pattern: mix in responder's static public key */
    noise_mix_hash(state->h, state->remote_static_public, 32);

    /* Generate ephemeral keypair */
    esp_fill_random(state->local_ephemeral_private, 32);
    state->local_ephemeral_private[0] &= 248;
    state->local_ephemeral_private[31] &= 127;
    state->local_ephemeral_private[31] |= 64;
    x25519_base(state->local_ephemeral_public, state->local_ephemeral_private, 1);

    state->handshake_complete = false;

    ESP_LOGI(TAG, "Noise IK initialized (protocol v%d)", ML_CTRL_PROTOCOL_VER);
}

/**
 * Build Noise message 1 (initiator -> responder)
 *
 * Layout: 5-byte header + 32B ephemeral + 48B encrypted_static + 16B auth_tag = 101 bytes
 *
 * Header: [version(2)][type(1)=0x01][length(2)=96]
 */
esp_err_t ml_noise_write_msg1(ml_noise_state_t *state, uint8_t *out, size_t *out_len) {
    size_t pos = 0;

    /* Header: version(2) + type(1) + payload_length(2) = 5 bytes */
    out[pos++] = (ML_CTRL_PROTOCOL_VER >> 8) & 0xFF;  /* version high */
    out[pos++] = ML_CTRL_PROTOCOL_VER & 0xFF;          /* version low (131 = 0x83) */
    out[pos++] = 0x01;  /* type: initiator */
    out[pos++] = 0x00;
    out[pos++] = 0x60;  /* length = 96 */

    /* e: Send ephemeral public key */
    memcpy(out + pos, state->local_ephemeral_public, 32);
    noise_mix_hash(state->h, state->local_ephemeral_public, 32);
    pos += 32;

    /* es: DH(ephemeral, remote_static) */
    uint8_t dh_output[32];
    x25519(dh_output, state->local_ephemeral_private, state->remote_static_public, 1);

    uint8_t k[32];
    noise_mix_key(state->ck, k, dh_output);
    memset(dh_output, 0, 32);

    /* s: Encrypt and send static public key (32 + 16 MAC = 48 bytes) */
    noise_aead_encrypt(k, 0, state->h, 32,
                        state->local_static_public, 32,
                        out + pos);
    noise_mix_hash(state->h, out + pos, 48);
    pos += 48;

    /* ss: DH(static, remote_static) */
    x25519(dh_output, state->local_static_private, state->remote_static_public, 1);
    noise_mix_key(state->ck, k, dh_output);
    memset(dh_output, 0, 32);

    /* Empty payload encrypted (just the 16-byte auth tag) */
    noise_aead_encrypt(k, 0, state->h, 32,
                        NULL, 0, out + pos);
    noise_mix_hash(state->h, out + pos, 16);
    pos += 16;

    memset(k, 0, 32);
    *out_len = pos;

    ESP_LOGI(TAG, "Noise msg1 built: %d bytes", (int)pos);
    return ESP_OK;
}

/**
 * Parse Noise message 2 (responder -> initiator)
 *
 * Receives RAW payload (3-byte Noise frame header already stripped by caller).
 * Expected: 32B ephemeral + 16B auth tag = 48 bytes (empty payload, IK pattern)
 *
 * Matches v1's noise_read_message_2() exactly.
 */
esp_err_t ml_noise_read_msg2(ml_noise_state_t *state, const uint8_t *msg, size_t len) {
    /* IK msg2 carries an empty payload: anything but exactly 48 bytes would
     * make the decrypt below write len-48 bytes through its NULL output. */
    if (len != 32 + 16) {
        ESP_LOGE(TAG, "Noise msg2 length %d (need exactly 48)", (int)len);
        return ESP_FAIL;
    }

    size_t offset = 0;
    uint8_t remote_ephemeral[32];
    uint8_t dh_output[32];
    uint8_t k[32];

    /* e: Read responder's ephemeral public key */
    memcpy(remote_ephemeral, msg + offset, 32);
    noise_mix_hash(state->h, remote_ephemeral, 32);
    offset += 32;

    /* ee: DH(our_ephemeral, their_ephemeral) */
    x25519(dh_output, state->local_ephemeral_private, remote_ephemeral, 1);
    noise_mix_key(state->ck, k, dh_output);

    /* se: DH(our_static, their_ephemeral) */
    x25519(dh_output, state->local_static_private, remote_ephemeral, 1);
    noise_mix_key(state->ck, k, dh_output);
    memset(dh_output, 0, 32);

    /* Decrypt payload (should be empty for IK — just 16-byte auth tag) */
    size_t ciphertext_len = len - offset;
    if (noise_aead_decrypt(k, 0, state->h, 32,
                            msg + offset, ciphertext_len,
                            NULL) != 0) {
        ESP_LOGE(TAG, "Noise msg2 auth tag verification failed");
        memset(k, 0, 32);
        return ESP_ERR_INVALID_MAC;
    }
    noise_mix_hash(state->h, msg + offset, ciphertext_len);

    /* Derive transport keys (Split operation) */
    noise_hkdf(state->ck, NULL, 0, state->tx_key, state->rx_key, NULL);
    state->tx_nonce = 0;
    state->rx_nonce = 0;
    state->handshake_complete = true;

    memset(k, 0, 32);
    ESP_LOGI(TAG, "Noise handshake complete - transport keys derived");
    return ESP_OK;
}

/* ============================================================================
 * Transport Encryption/Decryption
 * ========================================================================== */

esp_err_t ml_noise_encrypt(const uint8_t *key, uint64_t nonce,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *ciphertext) {
    if (noise_aead_encrypt(key, nonce, ad, ad_len,
                            plaintext, pt_len, ciphertext) != 0) {
        ESP_LOGE(TAG, "Noise encrypt failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t ml_noise_decrypt(const uint8_t *key, uint64_t nonce,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *ciphertext, size_t ct_len,
                            uint8_t *plaintext) {
    if (noise_aead_decrypt(key, nonce, ad, ad_len,
                            ciphertext, ct_len, plaintext) != 0) {
        ESP_LOGE(TAG, "Noise decrypt failed (nonce=%lu)", (unsigned long)nonce);
        return ESP_ERR_INVALID_MAC;
    }
    return ESP_OK;
}
