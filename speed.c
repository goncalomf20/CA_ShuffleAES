#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#define BLOCK_SIZE 16
#define BUFFER_SIZE 4096
#define NUM_MEASUREMENTS 100000

void cipher_saes(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void decipher_saes(unsigned char key[], unsigned char decipheredtext[16], int key_size, unsigned char cipher[16] , unsigned char sk[16]);
void cipher_saesNI(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
void decipher_saesNI(unsigned char key[16], unsigned char sk[16], unsigned char ciphertext[16], int key_size, unsigned char plaintext[16]);
void generate_keys_from_passwords(const char* password1, const char* password2, char* aes_key, char* sk);


double measure_time(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf(" %02x ", data[i]);
    }
    printf("\n");
}

void generate_password(char *password, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "0123456789"
                           "!@#$%^&*()_+";
    int charset_size = sizeof(charset) - 1;

    for (int i = 0; i < length; i++) {
        int key = rand() % charset_size;
        password[i] = charset[key];
    }
    password[length] = '\0';  
}

int main() {
    unsigned char buffer[BUFFER_SIZE]; 
    unsigned char aes_encrypted[BUFFER_SIZE];
    unsigned char saes_encrypted[BUFFER_SIZE];
    unsigned char saesNI_encrypted[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];

    unsigned char aes_key[16];
    unsigned char saes_key[16];
    unsigned char sk[16];
    char password1[16], password2[16];
    generate_password(password1, 16);
    generate_password(password2, 16);


    struct timespec start, end;
    double min_aes_encrypt_time = 1e12, min_aes_decrypt_time = 1e12;
    double min_saes_encrypt_time = 1e12, min_saes_decrypt_time = 1e12;
    double min_saesNI_encrypt_time = 1e12, min_saesNI_decrypt_time = 1e12;
    int fd = open("/dev/urandom", O_RDONLY);
    
    if (fd < 0) {
        perror("Error opening /dev/urandom");
        return 1;
    }

    if (read(fd, buffer, BUFFER_SIZE) < 0) {
        perror("Error reading /dev/urandom");
        close(fd);
        return 1;
    }
    close(fd);

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {

        AES_KEY enc_key;

        if (AES_set_encrypt_key(aes_key, 16 * 8, &enc_key) < 0) {
            fprintf(stderr, "Could not set encryption key\n");
        }
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int j = 0; j < BUFFER_SIZE; j += BLOCK_SIZE) {
            AES_encrypt(buffer + j, aes_encrypted + j, &enc_key);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double aes_encrypt_time = measure_time(start, end);
        if (aes_encrypt_time < min_aes_encrypt_time) min_aes_encrypt_time = aes_encrypt_time;

        // Measure AES library decryption time
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int j = 0; j < BUFFER_SIZE; j += BLOCK_SIZE) {
            AES_decrypt(aes_encrypted + j, decrypted + j, &enc_key);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double aes_decrypt_time = measure_time(start, end);
        if (aes_decrypt_time < min_aes_decrypt_time) min_aes_decrypt_time = aes_decrypt_time;

        // Measure S-AES encryption time
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int j = 0; j < BUFFER_SIZE; j += BLOCK_SIZE) {
            cipher_saes(saes_key, sk, buffer + j, 16, saes_encrypted + j);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double saes_encrypt_time = measure_time(start, end);
        if (saes_encrypt_time < min_saes_encrypt_time) min_saes_encrypt_time = saes_encrypt_time;

        // Measure S-AES decryption time
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int j = 0; j < BUFFER_SIZE; j += BLOCK_SIZE) {
            decipher_saes(saes_key, decrypted + j, 16, saes_encrypted + j, sk);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double saes_decrypt_time = measure_time(start, end);
        if (saes_decrypt_time < min_saes_decrypt_time) min_saes_decrypt_time = saes_decrypt_time;

        // Measure S-AES-NI encryption time
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int j = 0; j < BUFFER_SIZE; j += BLOCK_SIZE) {
            cipher_saesNI(saes_key, sk, buffer + j, 16, saesNI_encrypted + j);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double saesNI_encrypt_time = measure_time(start, end);
        if (saesNI_encrypt_time < min_saesNI_encrypt_time) min_saesNI_encrypt_time = saesNI_encrypt_time;

        // Measure S-AES-NI decryption time
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int j = 0; j < BUFFER_SIZE; j += BLOCK_SIZE) {
            decipher_saesNI(saes_key, sk, saesNI_encrypted + j, 16, decrypted + j);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double saesNI_decrypt_time = measure_time(start, end);
        if (saesNI_decrypt_time < min_saesNI_decrypt_time) min_saesNI_decrypt_time = saesNI_decrypt_time;
    
        
    }

    printf("Minimum AES (openssl) Encryption Time (ns): %.0f\n", min_aes_encrypt_time);
    printf("Minimum AES (openssl) Decryption Time (ns): %.0f\n", min_aes_decrypt_time);
    printf("Minimum S-AES Encryption Time (ns): %.0f\n", min_saes_encrypt_time);
    printf("Minimum S-AES Decryption Time (ns): %.0f\n", min_saes_decrypt_time);
    printf("Minimum S-AES-NI Encryption Time (ns): %.0f\n", min_saesNI_encrypt_time);
    printf("Minimum S-AES-NI Decryption Time (ns): %.0f\n", min_saesNI_decrypt_time);
    

    return 0;
}

void generate_random_key(unsigned char *key, int length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Error opening /dev/urandom for key generation");
        exit(1);
    }
    if (read(fd, key, length) != length) {
        perror("Error reading random key");
        close(fd);
        exit(1);
    }
    close(fd);
}
