#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

char** generate_keys_from_passwords(const char* password1, const char* password2) {
    const unsigned char salt[8] = {0}; 
    int iterations = 10000; // 10000 iterations was recommended by NIST in 2016
    static char* passwords[2];


    passwords[0] = PKCS5_PBKDF2_HMAC(password1, strlen(password1), salt, sizeof(salt), iterations, EVP_sha256(), 16);
    passwords[1] = PKCS5_PBKDF2_HMAC(password2, strlen(password2), salt, sizeof(salt), iterations, EVP_sha256(), 16);
    return passwords;
}




