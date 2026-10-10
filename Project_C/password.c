#include "password.h"
#include "pbkdf2.h"
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
  #include <windows.h>
  /* Some MinGW installations provide the CNG library but not bcrypt.h. */
  #ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
    #define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
  #endif
  typedef LONG NTSTATUS;
  typedef void *BCRYPT_ALG_HANDLE;
    typedef NTSTATUS (WINAPI *BCryptGenRandomFn)(
      BCRYPT_ALG_HANDLE hAlgorithm,
      PUCHAR pbBuffer,
      ULONG cbBuffer,
      ULONG dwFlags);

  int random_bytes(uint8_t *out, size_t len) {
      HMODULE bcrypt = LoadLibraryA("bcrypt.dll");
      if (bcrypt == NULL) return -1;

      BCryptGenRandomFn gen_random =
        (BCryptGenRandomFn)GetProcAddress(bcrypt, "BCryptGenRandom");
      if (gen_random == NULL) {
        FreeLibrary(bcrypt);
        return -1;
      }

      NTSTATUS s = gen_random(NULL, out, (ULONG)len,
                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      FreeLibrary(bcrypt);
      return (s == 0) ? 0 : -1;
  }
#else
  #include <fcntl.h>
  #include <unistd.h>

  int random_bytes(uint8_t *out, size_t len) {
      int fd = open("/dev/urandom", O_RDONLY);
      if (fd < 0) return -1;
      ssize_t n = read(fd, out, len);
      close(fd);
      return (n == (ssize_t)len) ? 0 : -1;
  }
#endif

void derive_hash(const char *password,
                 const uint8_t *salt, size_t salt_len,
                 int iterations,
                 uint8_t out[HASH_LEN])
{
    pbkdf2_sha256(password, strlen(password),
                  salt, salt_len,
                  iterations,
                  out, HASH_LEN);
}

int secure_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}