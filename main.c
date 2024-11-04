#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void cipher_openssl_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void cipher_our_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void cipher_saes(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void generate_keys_from_passwords(const char* password1, const char* password2, char* aes_key, char* sk);

void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {

    unsigned char key[32]; // Buffer for key (256 bits)
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
        if (choice != 2) {

            while ( key_size < 1 || key_size > 3) {
                printf("Select key size (128, 192, 256 bits):\n");
                printf("1. 128 bits\n");
                printf("2. 192 bits\n");
                printf("3. 256 bits\n");
                printf("Enter your choice: ");
                scanf("%d", &key_size);
            }

            switch (key_size) {
                case 1:
                    // 128 bits (16 bytes)
                    memcpy(key, "0123456789abcdef", 16); // 16 bytes
                    key_size = 16;
                    break;
                case 2:
                    // 192 bits (24 bytes)
                    memcpy(key, "0123456789abcdef01234567", 24); // 24 bytes
                    key_size = 24;

                    break;
                case 3:
                    // 256 bits (32 bytes)
                    memcpy(key, "0123456789abcdef0123456789abcdef", 32); // 32 bytes
                    key_size = 32;
                    break;
            }
            printf("---> Key (hex): ");
            print_hex(key, key_size);
        }
        
        printf("---> Plaintext (hex): ");
        print_hex(plaintext, 16);

        memset(cipher, 0, 16); 
        
        switch (choice) {
            case 1:
                cipher_our_aes(key, plaintext, key_size, cipher);
               
                printf("---> Encrypted text (hex): ");
                print_hex(cipher, 16); 
                    
                break;
            case 2:
                char key1[100], key2[100];

                printf("---> Insert the fist key: ");
                scanf("%99s", key1); 

                printf("---> Insert the second key: ");
                scanf("%99s", key2);  

                printf("You entered: Key1 = %s, Key2 = %s\n", key1, key2);

                char aes_key[16];  // AES encryption key (128-bit)
                char sk[16];       // Shuffling key (128-bit)
                generate_keys_from_passwords(key1, key2, aes_key, sk);
                
                printf("\nAes Key = ");
                print_hex(aes_key, 16); 
                printf("Shuffled Key = ");
                print_hex(sk, 16); 


                cipher_saes(aes_key, sk, plaintext, 16, cipher);

                
                printf("---> Encrypted text (hex): ");
                print_hex(cipher, 16);

                decipher_saes(key, cipher, key_size, cipher, sk);
                printf("---> Decrypted text (hex): ");
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
                // unsigned char saes_cipher[16];
                
                cipher_our_aes(key, plaintext, key_size, our_cipher);
                cipher_openssl_aes(key, plaintext, key_size, openssl_cipher);
                // cipher_saes(key, plaintext, key_size, saes_cipher);

                printf("------> Encrypted text (our) (hex): ");
                print_hex(our_cipher, 16);

                printf("------> Encrypted text (openssl) (hex): ");
                print_hex(openssl_cipher, 16);

                // printf("------> Encrypted text (saes) (hex): ");
                // print_hex(saes_cipher, 16);

                break;
        }

    }

    
}
