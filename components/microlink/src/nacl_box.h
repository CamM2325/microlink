/**
 * @file nacl_box.h
 * @brief Minimal NaCl crypto_box implementation for Tailscale challenge response
 *
 * Implements crypto_box_seal using X25519 + XSalsa20-Poly1305
 */

#ifndef _NACL_BOX_H_
#define _NACL_BOX_H_

#include <stdint.h>
#include <stddef.h>

#define NACL_BOX_NONCEBYTES 24
#define NACL_BOX_MACBYTES 16
#define NACL_BOX_PUBLICKEYBYTES 32
#define NACL_BOX_SECRETKEYBYTES 32

/**
 * @brief Encrypt a message using NaCl crypto_box
 *
 * Uses X25519 shared secret + HSalsa20 key derivation + XSalsa20-Poly1305
 *
 * @param ciphertext Output buffer (must be plaintext_len + NACL_BOX_MACBYTES)
 * @param plaintext Input message
 * @param plaintext_len Length of plaintext
 * @param nonce 24-byte nonce
 * @param recipient_pk Recipient's public key (32 bytes)
 * @param sender_sk Sender's secret key (32 bytes)
 * @return 0 on success, -1 on failure
 */
int nacl_box(uint8_t *ciphertext,
             const uint8_t *plaintext, size_t plaintext_len,
             const uint8_t *nonce,
             const uint8_t *recipient_pk,
             const uint8_t *sender_sk);

/**
 * @brief Compute shared secret for NaCl box (HSalsa20 of X25519 result)
 *
 * @param shared_key Output 32-byte shared key
 * @param recipient_pk Recipient's public key
 * @param sender_sk Sender's secret key
 * @return 0 on success, -1 on failure
 */
int nacl_box_beforenm(uint8_t *shared_key,
                      const uint8_t *recipient_pk,
                      const uint8_t *sender_sk);

/**
 * @brief Encrypt using precomputed shared key
 *
 * @param ciphertext Output (plaintext_len + NACL_BOX_MACBYTES)
 * @param plaintext Input message
 * @param plaintext_len Length of plaintext
 * @param nonce 24-byte nonce
 * @param shared_key Precomputed shared key from nacl_box_beforenm
 * @return 0 on success, -1 on failure
 */
int nacl_box_afternm(uint8_t *ciphertext,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *nonce,
                     const uint8_t *shared_key);

/**
 * @brief Decrypt a message using NaCl crypto_box_open
 *
 * Verifies Poly1305 MAC then decrypts with XSalsa20.
 *
 * @param plaintext Output buffer (must be ciphertext_len - NACL_BOX_MACBYTES)
 * @param ciphertext Input (MAC || encrypted data)
 * @param ciphertext_len Length of ciphertext (including MAC)
 * @param nonce 24-byte nonce
 * @param sender_pk Sender's public key (32 bytes)
 * @param recipient_sk Recipient's secret key (32 bytes)
 * @return 0 on success, -1 on MAC verification failure
 */
int nacl_box_open(uint8_t *plaintext,
                  const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *nonce,
                  const uint8_t *sender_pk,
                  const uint8_t *recipient_sk);

/**
 * @brief Decrypt using precomputed shared key
 *
 * @param plaintext Output (ciphertext_len - NACL_BOX_MACBYTES)
 * @param ciphertext Input (MAC || encrypted data)
 * @param ciphertext_len Length of ciphertext (including MAC)
 * @param nonce 24-byte nonce
 * @param shared_key Precomputed shared key from nacl_box_beforenm
 * @return 0 on success, -1 on MAC verification failure
 */
int nacl_box_open_afternm(uint8_t *plaintext,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *nonce,
                          const uint8_t *shared_key);

/**
 * @brief Shared key for (peer_pk, our_sk), memoised across calls.
 *
 * nacl_box_beforenm() is an X25519 scalar multiplication, which costs roughly
 * 30 ms on an ESP32-S3. DISCO performs one per packet in each direction, so on
 * a tailnet of any size the WireGuard manager task spends most of its time
 * recomputing the same handful of shared secrets. Our own secret key is fixed
 * for the node's lifetime, so the result depends only on the peer's public key
 * and can be cached.
 *
 * @param shared_key Output 32-byte shared key
 * @param peer_pk    Peer's public key (32 bytes) - the cache key
 * @param our_sk     Our secret key (32 bytes)
 * @return 0 on success, -1 on failure
 */
int nacl_box_shared_get(uint8_t *shared_key,
                        const uint8_t *peer_pk,
                        const uint8_t *our_sk);

#endif /* _NACL_BOX_H_ */
