#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void generate_keys_from_passwords(const char* password1, const char* password2, char* aes_key, char* sk) {
    unsigned char salt1[8];
    unsigned char salt2[8];
    int iterations = 10000;

    // Generate random salts
    if (RAND_bytes(salt1, sizeof(salt1)) != 1 || RAND_bytes(salt2, sizeof(salt2)) != 1) {
        fprintf(stderr, "Failed to generate salt\n");
        return;
    }

    PKCS5_PBKDF2_HMAC(password1, strlen(password1), salt1, sizeof(salt1), iterations, EVP_sha256(), 16, aes_key);
    PKCS5_PBKDF2_HMAC(password2, strlen(password2), salt2, sizeof(salt2), iterations, EVP_sha256(), 16, sk);
}


// int main(int argc, char* argv[]) {
//     if (argc < 3) {
//         fprintf(stderr, "Usage: %s <password1> <password2>\n", argv[0]);
//         return 1;
//     }

//     // Generate AES key and SK key
//     uint8_t aes_key[16];  // AES encryption key (128-bit)
//     uint8_t sk[16];       // Shuffling key (128-bit)
//     generate_keys_from_passwords(argv[1], argv[2], aes_key, sk);

//     // Print the generated keys
//     printf("AES Key: ");
//     for (int i = 0; i < 16; i++) {
//         printf("%02x", aes_key[i]);
//     }
//     printf("\n");

//     printf("SK Key: ");
//     for (int i = 0; i < 16; i++) {
//         printf("%02x", sk[i]);
//     }
//     printf("\n");

//     return 0;
// }
