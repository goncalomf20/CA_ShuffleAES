#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void generate_keys_from_passwords(const char* password1, const char* password2, char* aes_key, char* sk) {
    unsigned char salt[8] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}; // Fixed salt
    int iterations = 10000;

    PKCS5_PBKDF2_HMAC(password1, strlen(password1), salt, sizeof(salt), iterations, EVP_sha256(), 16, aes_key);
    PKCS5_PBKDF2_HMAC(password2, strlen(password2), salt, sizeof(salt), iterations, EVP_sha256(), 16, sk);
}



