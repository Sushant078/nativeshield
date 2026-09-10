#ifndef SHIELD_CRYPTO_H
#define SHIELD_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

/* Self-contained SHA-256 / HMAC-SHA256 / HKDF-SHA256 (RFC 6234 / RFC 5869).
 * No external crypto dependency so the .so stays small and portable. */

#define SHIELD_SHA256_LEN 32

void shield_sha256(const uint8_t *data, size_t len, uint8_t out[SHIELD_SHA256_LEN]);

void shield_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[SHIELD_SHA256_LEN]);

/* HKDF-SHA256; out_len must be <= 255*32. Returns 0 on success. */
int shield_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len);

/* Constant-time equality: returns 1 if equal, 0 otherwise. */
int shield_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);

#endif
