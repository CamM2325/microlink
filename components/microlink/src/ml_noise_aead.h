/**
 * @file ml_noise_aead.h
 * @brief ChaCha20-Poly1305 for the Noise control channel
 *
 * Uses the RFC 8439 reference implementation bundled with wireguard-lwip
 * (crypto/refc/chacha20poly1305.c) instead of mbedTLS, whose ChaCha20-Poly1305
 * API became private in mbedTLS 4 (ESP-IDF 6). The same code is used on every
 * ESP-IDF version. Header-only so test/host can check it against RFC 8439.
 *
 * Nonce layout: Tailscale uses 4 zero bytes followed by the 64-bit counter in
 * BIG-endian (Go: binary.BigEndian.PutUint64(n[4:], counter)). wireguard-lwip
 * uses 4 zero bytes followed by the counter in LITTLE-endian, so the counter
 * is passed byte-swapped.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "chacha20poly1305.h"

/* ciphertext layout: encrypted data (pt_len bytes) followed by the 16-byte tag.
 * plaintext may be NULL when pt_len == 0. Always succeeds (returns 0). */
static inline int noise_aead_encrypt(const uint8_t *key, uint64_t nonce,
                                     const uint8_t *ad, size_t ad_len,
                                     const uint8_t *plaintext, size_t pt_len,
                                     uint8_t *ciphertext)
{
    chacha20poly1305_encrypt(ciphertext, plaintext, pt_len, ad, ad_len,
                             __builtin_bswap64(nonce), key);
    return 0;
}

/* Returns 0 if the tag verifies, -1 otherwise (including ct_len < 16).
 * plaintext (ct_len - 16 bytes, may be NULL when that is 0) is written only
 * when the tag verifies. */
static inline int noise_aead_decrypt(const uint8_t *key, uint64_t nonce,
                                     const uint8_t *ad, size_t ad_len,
                                     const uint8_t *ciphertext, size_t ct_len,
                                     uint8_t *plaintext)
{
    if (ct_len < 16) return -1;
    return chacha20poly1305_decrypt(plaintext, ciphertext, ct_len, ad, ad_len,
                                    __builtin_bswap64(nonce), key) ? 0 : -1;
}
