#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

void cipher_openssl_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]) {
    AES_KEY enc_key;  // Structure to hold the AES key

    // Set encryption key depending on the key size (128, 192, or 256 bits)
    if (AES_set_encrypt_key(key, key_size * 8, &enc_key) < 0) {
        fprintf(stderr, "Could not set encryption key\n");
    }

    AES_encrypt(plaintext, cipher, &enc_key);

}
