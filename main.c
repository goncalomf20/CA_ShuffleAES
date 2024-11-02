#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void cipher_openssl_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void cipher_our_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void cipher_saes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
char** generate_keys_from_passwords(const char* password1, const char* password2);


void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {

    unsigned char key[32]; // Buffer for key (256 bits)
    unsigned char key_sh[16]; // Buffer for shuffling key (128 bits)
    unsigned char plaintext[16] = "Hello, World!!!!"; // 128-bit plaintext
    unsigned char cipher[16];


    while (true) {
               
        int choice = 0;
        while ( choice < 1 || choice > 5) { 
            printf("Select the algorithm to use:\n");
            printf("1. our AES\n");
            printf("2. SAES\n");
            printf("3. openssl AES\n");
            printf("4. all\n");
            printf("5. exit\n");

            printf("Enter your choice: ");
            scanf("%d", &choice);
        }
        

        if (choice == 5) {
            printf("End");
            break;
        }
        
        memset(key, 0, 32); 
        int key_size = 0;
        int size;
        while ( key_size < 1 || key_size > 3) {
            printf("Select key size (128, 192, 256 bits):\n");
            printf("1. 128 bits\n");
            printf("2. 192 bits\n");
            printf("3. 256 bits\n");
            printf("Enter your choice: ");
            scanf("%d", &key_size);
        }

        switch (key_size) {
            //stdin to key
            case 1:
                printf("Enter key (16 bytes): ");
                fgets(key, 16, stdin);
                // 128 bits (16 bytes)
                memcpy(key, "0123456789abcdef", 16); // 16 bytes
                key_size = 16;
                size = 128;
                break;
            case 2:
                printf("Enter key (24 bytes): ");
                fgets(key, 24, stdin);
                // 192 bits (24 bytes)
                memcpy(key, "0123456789abcdef01234567", 24); // 24 bytes
                key_size = 24;
                size = 192;
                break;
            case 3:
                printf("Enter key (32 bytes): ");
                fgets(key, 32, stdin);
                memcpy(key, "0123456789abcdef0123456789abcdef", 32); // 32 bytes
                key_size = 32;
                size = 256;
                break;
        }
        printf("---> Key (hex): ");
        print_hex(key, key_size);
        
        printf("---> Plaintext (hex): ");
        print_hex(plaintext, 16);

        memset(cipher, 0, 16); 
        
        switch (choice) {
            case 1:
                cipher_our_aes(key, plaintext, size , cipher);
               
                printf("---> Encrypted text (hex): ");
                print_hex(cipher, 16); 
                    
                break;
            case 2:
                printf("Enter the SK (16 bytes): ");
                fgets(key_sh, 16, stdin);
                char** passwords; 
                passwords = generate_keys_from_passwords(key, key_sh);
                memcpy(key, passwords[0], 16); // 16 bytes
                memcpy(key_sh, passwords[1], 16); // 16 bytes
                printf("---> Key (hex): ");
                print_hex(key, 16);
                cipher_saes(key, plaintext, key_size, cipher);
                
                printf("---> Encrypted text (hex): ");
                print_hex(cipher, 16);

                break;
            case 3:
                cipher_openssl_aes(key, plaintext, key_size, cipher);
                
                printf("---> Encrypted text (hex): ");
                print_hex(cipher, 16);
                   
                break;
            case 4:
                unsigned char our_cipher[16];
                unsigned char openssl_cipher[16];
                unsigned char saes_cipher[16];
                
                cipher_our_aes(key, plaintext, key_size, our_cipher);
                cipher_openssl_aes(key, plaintext, key_size, openssl_cipher);
                cipher_saes(key, plaintext, key_size, saes_cipher);

                printf("------> Encrypted text (our) (hex): ");
                print_hex(our_cipher, 16);

                printf("------> Encrypted text (openssl) (hex): ");
                print_hex(openssl_cipher, 16);

                 printf("------> Encrypted text (saes) (hex): ");
                print_hex(saes_cipher, 16);

                break;

            
        }

    }

    
}
