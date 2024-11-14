#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

void cipher_openssl_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]) {
    AES_KEY enc_key;  
    if (AES_set_encrypt_key(key, key_size * 8, &enc_key) < 0) {
        fprintf(stderr, "Could not set encryption key\n");
    }

    AES_encrypt(plaintext, cipher, &enc_key);

}

void decipher_openssl_aes(unsigned char key[], unsigned char cipher[16], int key_size, unsigned char decipheredtext[16]) {
    AES_KEY dec_key;  

    if (AES_set_decrypt_key(key, key_size * 8, &dec_key) < 0) {
        fprintf(stderr, "Could not set decryption key\n");
    }

    AES_decrypt(cipher, decipheredtext, &dec_key);
}
