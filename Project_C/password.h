#ifndef PASSWORD_H
#define PASSWORD_H

#include <stdint.h>
#include <stddef.h>

#define SALT_LEN 16
#define HASH_LEN 32
#define PBKDF2_ITER 100000

/* Fill `out` with `len` cryptographically random bytes. */
int random_bytes(uint8_t *out, size_t len);

/* Derive a hash from password + salt. */
void derive_hash(const char *password,
                 const uint8_t *salt, size_t salt_len,
                 int iterations,
                 uint8_t out[HASH_LEN]);

/* Constant-time comparison: returns 1 if equal, 0 otherwise. */
int secure_compare(const uint8_t *a, const uint8_t *b, size_t len);

#endif