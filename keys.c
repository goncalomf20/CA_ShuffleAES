#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>



void generate_keys_from_passwords(const char* password1, const char* password2, uint8_t* aes_key, uint8_t* sk) {
    const unsigned char salt[8] = {0}; 
    int iterations = 10000; // 10000 iterations was recommended by NIST in 2016

    PKCS5_PBKDF2_HMAC(password1, strlen(password1), salt, sizeof(salt), iterations, EVP_sha256(), 16, aes_key);

    PKCS5_PBKDF2_HMAC(password2, strlen(password2), salt, sizeof(salt), iterations, EVP_sha256(), 16, sk);
}



int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <password1> <password2>\n", argv[0]);
        return 1;
    }

    // Generate AES key and SK key
    uint8_t aes_key[16];  // AES encryption key (128-bit)
    uint8_t sk[16];       // Shuffling key (128-bit)
    generate_keys_from_passwords(argv[1], argv[2], aes_key, sk);

    // Print the generated keys
    printf("AES Key: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    printf("SK Key: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", sk[i]);
    }
    printf("\n");

    return 0;
}
