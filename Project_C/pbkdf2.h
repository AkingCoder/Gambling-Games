#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>
#include <stddef.h>

void pbkdf2_sha256(const char *password, size_t password_len,
                   const uint8_t *salt, size_t salt_len,
                   int iterations,
                   uint8_t *out, size_t out_len);

#endif