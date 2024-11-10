#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define BLOCK_SIZE 16

void cipher_openssl_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void cipher_our_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void cipher_saes(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void generate_keys_from_passwords(const char* password1, const char* password2, char* aes_key, char* sk);
void cipher_saesNI(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void decipher_saesNI(unsigned char key[16], unsigned char sk[16], unsigned char ciphertext[16], int key_size, unsigned char plaintext[16]);

void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf(" %02x ", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {


    if (argc == 2) {
        const char *password1 = argv[1];
        printf("Password 1: %s\n", password1);
        char aes_key[16];  // AES encryption key (128-bit)
        char sk[16];       // Shuffling key (128-bit)
        generate_keys_from_passwords(password1, password1, aes_key, sk);
        printf("\nAes Key = ");
        print_hex(aes_key, 16); 

        unsigned char plaintext[256];
        printf("Enter a message: ");
        fgets((char *)plaintext, 256, stdin);


        int len = strlen((char *)plaintext);
        int blocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;

        // Allocate memory for padded plaintext and cipher output
        unsigned char *padded_plaintext = malloc(blocks * BLOCK_SIZE);
        unsigned char *cipher = malloc(blocks * BLOCK_SIZE + 1);

        // Copy plaintext to padded_plaintext and add PKCS#7 padding if needed
        memcpy(padded_plaintext, plaintext, len);
        int padding = BLOCK_SIZE - (len % BLOCK_SIZE);
        
        if (padding == 16){
            padding = 0;
        }
        for (int i = 0; i < padding; i++) {
            padded_plaintext[len + i] = padding;
        }

        // Encrypt each block
        printf("Encrypted message (OpenSSL): ");
        for (int i = 0; i < blocks; i++) {
            cipher_openssl_aes(aes_key, padded_plaintext + i * BLOCK_SIZE, 16, cipher + i * BLOCK_SIZE);
            print_hex(cipher + i * BLOCK_SIZE, BLOCK_SIZE);
        }

        printf("Encrypted message (Our_AES): ");
        for (int i = 0; i < blocks; i++) {
            cipher_our_aes(aes_key, padded_plaintext + i * BLOCK_SIZE, 16, cipher + i * BLOCK_SIZE);
            print_hex(cipher + i * BLOCK_SIZE, BLOCK_SIZE);    
        }

    
        free(padded_plaintext);
        free(cipher);
        return 0;

    } 
    else if (argc == 3)
    {
    const char *password1 = argv[1];
    const char *password2 = argv[2];

    printf("Password 1: %s\n", password1);
    printf("Password 2: %s\n", password2);

    char aes_key[16];  // AES encryption key (128-bit)
    char sk[16];       // Shuffling key (128-bit)
    generate_keys_from_passwords(password1, password2, aes_key, sk);
    
    printf("\nAes Key = ");
    print_hex(aes_key, 16); 
    printf("Shuffled Key = ");
    print_hex(sk, 16); 

    printf("\n");

    unsigned char plaintext[256];
    printf("Enter a message: ");
    fgets((char *)plaintext, 256, stdin);

    int len = strlen((char *)plaintext);    
    int blocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    // Allocate memory for padded plaintext and cipher output
    unsigned char *padded_plaintext = malloc(blocks * BLOCK_SIZE);
    unsigned char *cipher = malloc(blocks * BLOCK_SIZE);

    // Copy plaintext to padded_plaintext and add PKCS#7 padding if needed
    memcpy(padded_plaintext, plaintext, len);
    int padding = BLOCK_SIZE - (len % BLOCK_SIZE);
    if (padding == 16){
        padding = 0;
    }
    for (int i = 0; i < padding; i++) {
        padded_plaintext[len + i] = padding;
    }


    // Encrypt each block
    printf("Encrypted message (SAES): ");
    for (int i = 0; i < blocks; i++) {
        cipher_saes(aes_key, sk, padded_plaintext + i * BLOCK_SIZE, BLOCK_SIZE, cipher + i * BLOCK_SIZE);
    }
    print_hex(cipher, BLOCK_SIZE * blocks);

    printf("Encrypted message (SAES-NI): ");
    for (int i = 0; i < blocks; i++) {
        cipher_saesNI(aes_key, sk, padded_plaintext + i * BLOCK_SIZE, BLOCK_SIZE, cipher + i * BLOCK_SIZE);
    }
    print_hex(cipher, BLOCK_SIZE * blocks);

    free(padded_plaintext);
    free(cipher);
    return 0;
    }
    else {    
        fprintf(stderr, "Usage: %s <password1> <password2>\n", argv[0]);
        fprintf(stderr, "Usage: %s <password1>\n", argv[0]);
        return 1;
    }
    

}