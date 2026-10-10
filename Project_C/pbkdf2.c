#include "pbkdf2.h"
#include "sha256.h"
#include <string.h>
#include <stdlib.h>

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32])
{
    uint8_t k[64] = {0};
    uint8_t ipad[64], opad[64];
    uint8_t inner[32];
    SHA256_CTX ctx;

    if (key_len > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

void pbkdf2_sha256(const char *password, size_t password_len,
                   const uint8_t *salt, size_t salt_len,
                   int iterations,
                   uint8_t *out, size_t out_len)
{
    uint32_t block_num = 1;
    size_t generated = 0;

    while (generated < out_len) {
        uint8_t U[32], T[32];
        uint8_t block[4] = {
            (block_num >> 24) & 0xff,
            (block_num >> 16) & 0xff,
            (block_num >>  8) & 0xff,
            (block_num      ) & 0xff
        };

        size_t buf_len = salt_len + 4;
        uint8_t *buf = malloc(buf_len);
        memcpy(buf, salt, salt_len);
        memcpy(buf + salt_len, block, 4);

        hmac_sha256((const uint8_t *)password, password_len, buf, buf_len, U);
        free(buf);
        memcpy(T, U, 32);

        for (int i = 1; i < iterations; i++) {
            hmac_sha256((const uint8_t *)password, password_len, U, 32, U);
            for (int j = 0; j < 32; j++) T[j] ^= U[j];
        }

        size_t take = out_len - generated;
        if (take > 32) take = 32;
        memcpy(out + generated, T, take);
        generated += take;
        block_num++;
    }
}