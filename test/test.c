#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void cipher_our_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);

void decipher_our_aes(unsigned char key[], unsigned char decipheredtext[16], int key_size, unsigned char cipher[16]);


void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf(" %02x ", data[i]);
    }
    printf("\n");
}

int main() {

    unsigned char key[16] = "kkkkeeeeyyyy...."; // Buffer for key (256 bits)
    unsigned char plaintext[16] = "abcdef1234567890"; // 128-bit plaintext
    unsigned char cipher[16];
    unsigned char decipheredtext[16];

    int key_size = 16;

        
    printf("---> Key (hex): ");
    print_hex(key, key_size);
        
    printf("---> Plaintext (hex): ");
    print_hex(plaintext, 16);

    printf("\n");
    cipher_our_aes(key, plaintext, key_size, cipher);
               
    // printf("---> Encrypted text (hex): ");
    // print_hex(cipher, 16); 

    decipher_our_aes(key, decipheredtext, key_size, cipher );


    
}
