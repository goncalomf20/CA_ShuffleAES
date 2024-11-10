#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#define BLOCK_SIZE 16

void cipher_openssl_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void cipher_our_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void cipher_saes(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void generate_keys_from_passwords(const char* password1, const char* password2, char* aes_key, char* sk);
void cipher_saesNI(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void decipher_saes(unsigned char key[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16],  unsigned char sk[16]);
void decipher_saesNI(unsigned char key[16], unsigned char sk[16], unsigned char ciphertext[16], int key_size, unsigned char plaintext[16]);
void decipher_our_aes(unsigned char key[], unsigned char decipheredtext[16], int key_size, unsigned char cipher[16]);
void decipher_openssl_aes(unsigned char key[], unsigned char cipher[16], int key_size, unsigned char decipheredtext[16]);

void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf(" %02x ", data[i]);
    }
    printf("\n");
}


int hex_to_bytes(const char *hex_str, unsigned char *bytes, int max_len) {
    int len = strlen(hex_str);
    int byte_len = 0;

    for (int i = 0; i < len && byte_len < max_len; i += 2) {
        // Skip spaces
        while (hex_str[i] == ' ') i++;
        if (hex_str[i] == '\0' || hex_str[i + 1] == '\0') break;

        // Convert two hex characters to one byte
        sscanf(hex_str + i, "%2hhx", &bytes[byte_len]);
        byte_len++;
    }
    return byte_len;
}

int main(int argc, char *argv[]) {


    if (argc == 2) {
        const char *password1 = argv[1];
    const char *password2 = argv[2];

    printf("Password 1: %s\n", password1);

    char aes_key[16];  // AES encryption key (128-bit)
    char sk[16];       // Shuffling key (128-bit)
    generate_keys_from_passwords(password1, password1, aes_key, sk);

    printf("\nAES Key = ");
    print_hex((unsigned char *)aes_key, 16);

    unsigned char cipher[256];
    char hex_input[513];
    
    printf("Enter a cipher (in hex format with spaces): ");
    fgets(hex_input, sizeof(hex_input), stdin);  // Use fgets to read entire line

    // Remove spaces and convert to bytes
    int len = hex_to_bytes(hex_input, cipher, sizeof(cipher));
    if (len < 0) {
        printf("Error: Cipher hex input is too long.\n");
        return 1;
    }

    printf("Cipher: ");
    print_hex(cipher, len);

    int blocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    // Allocate memory for padded cipher and plaintext output
    unsigned char *padded_cipher = malloc(blocks * BLOCK_SIZE);
    unsigned char *plaintext = malloc(blocks * BLOCK_SIZE);
    


    // Decrypt each block
    printf("Decrypted message (OUR AES): ");
    for (int i = 0; i < blocks; i++) {
        decipher_our_aes(aes_key, plaintext + i * BLOCK_SIZE, 16, cipher + i * BLOCK_SIZE);
        print_hex(plaintext + i * BLOCK_SIZE, BLOCK_SIZE);
    }

    printf("Decrypted message (OPENSSL): ");
    for (int i = 0; i < blocks; i++) {
        decipher_openssl_aes(aes_key, cipher + i * BLOCK_SIZE, 16, plaintext + i * BLOCK_SIZE);
        print_hex(plaintext + i * BLOCK_SIZE, BLOCK_SIZE);
    }

    printf("Plaintext: ");
    for (int i = 0; i < blocks; i++) {
        for (int j = 0; j < BLOCK_SIZE; j++) {
            printf("%c", isprint(plaintext[i * BLOCK_SIZE + j]) ? plaintext[i * BLOCK_SIZE + j] : ' ');
        }
    }
    printf("\n");
    

    free(padded_cipher);
    free(plaintext);
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
    
    printf("\nAES Key = "); 
    print_hex((unsigned char *)aes_key, 16); 
    printf("Shuffled Key = ");
    print_hex((unsigned char *)sk, 16); 
    printf("\n");

    unsigned char cipher[256];
    char hex_input[513];
    
    printf("Enter a cipher (in hex format with spaces): ");
    fgets(hex_input, sizeof(hex_input), stdin);  // Use fgets to read entire line

    // Remove spaces and convert to bytes
    int len = hex_to_bytes(hex_input, cipher, sizeof(cipher));
    if (len < 0) {
        printf("Error: Cipher hex input is too long.\n");
        return 1;
    }

    printf("Cipher: ");
    print_hex(cipher, len);

    int blocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    // Allocate memory for padded cipher and plaintext output
    unsigned char *padded_cipher = malloc(blocks * BLOCK_SIZE);
    unsigned char *plaintext = malloc(blocks * BLOCK_SIZE);


    // Decrypt each block
    printf("Decrypted message (SAES): ");
    for (int i = 0; i < blocks; i++) {
        decipher_saes(aes_key, plaintext + i * BLOCK_SIZE ,16 ,cipher + i * BLOCK_SIZE, sk);
        print_hex(plaintext + i * BLOCK_SIZE, BLOCK_SIZE);
    }

    printf("Decrypted message (SAES-NI): ");
    for (int i = 0; i < blocks; i++) {
        decipher_saesNI(aes_key, sk, cipher + i * BLOCK_SIZE, 16, plaintext + i * BLOCK_SIZE);
        print_hex(plaintext + i * BLOCK_SIZE, BLOCK_SIZE);
    }

    printf("Plaintext: ");
    for (int i = 0; i < blocks; i++) {
        for (int j = 0; j < BLOCK_SIZE; j++) {
            printf("%c", isprint(plaintext[i * BLOCK_SIZE + j]) ? plaintext[i * BLOCK_SIZE + j] : ' ');
        }
    }
    printf("\n");
    

    free(padded_cipher);
    free(plaintext);
    return 0;
    }
    else {    
        fprintf(stderr, "Usage: %s <password1> <password2>\n", argv[0]);
        fprintf(stderr, "Usage: %s <password1>\n", argv[0]);
        return 1;
    }
    

}