#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

unsigned char Rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1f, 0x7b, 0xf6, 0xe1, 0xc7, 0x9e,
    0x27, 0x4e, 0x9c, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1f, 0x7b, 0xf6, 0xe1, 0xc7, 0x9e,
    0x27, 0x4e, 0x9c, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
};

void key_schedule_core(unsigned char *word, unsigned char i);
void expandKey(unsigned char *expandedKey, unsigned char *key, unsigned int key_size, unsigned int expandedKeySize);
void subBytes(unsigned char *state);
void shiftRows(unsigned char *state);
void addRoundKey(unsigned char *state, unsigned char *roundKey);
void mixColumns(unsigned char *state);
void cipher_our_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]);
unsigned char galois_multiplication(unsigned char a, unsigned char b);

unsigned char galois_multiplication(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char counter;
    unsigned char hi_bit_set;
    for (counter = 0; counter < 8; counter++) {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void key_schedule_core(unsigned char *word, unsigned char i) {
    unsigned char temp = word[0];
    for (int j = 0; j < 3; j++) {
        word[j] = word[j + 1];
    }
    word[3] = temp;
    for (int j = 0; j < 4; j++) {
        word[j] = sbox[word[j]];
    }
    word[0] ^= Rcon[i];
}

void expandKey(unsigned char *expandedKey, unsigned char *key, unsigned int key_size, unsigned int expandedKeySize) {
    unsigned int bytesInKey = key_size / 8;
    unsigned int wordsInKey = bytesInKey / 4;
    unsigned int rconIndex = 1;
    for (unsigned int i = 0; i < bytesInKey; i++) {
        expandedKey[i] = key[i];
    }
    unsigned int i = bytesInKey;
    while (i < expandedKeySize) {
        unsigned char temp[4];
        for (int j = 0; j < 4; j++) {
            temp[j] = expandedKey[i - 4 + j];
        }
        if (i % bytesInKey == 0) {
            key_schedule_core(temp, rconIndex++);
        }
        for (int j = 0; j < 4; j++) {
            expandedKey[i] = expandedKey[i - bytesInKey] ^ temp[j];
            i++;
        }
    }
}

void subBytes(unsigned char *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

void shiftRows(unsigned char *state) {
    unsigned char temp;
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

void addRoundKey(unsigned char *state, unsigned char *roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

void mixColumns(unsigned char *state) {
    unsigned char tmp[16];
    for (int i = 0; i < 4; i++) {
        tmp[i * 4] = galois_multiplication(state[i * 4], 2) ^
                     galois_multiplication(state[i * 4 + 1], 3) ^
                     state[i * 4 + 2] ^
                     state[i * 4 + 3];
        tmp[i * 4 + 1] = state[i * 4] ^
                         galois_multiplication(state[i * 4 + 1], 2) ^
                         galois_multiplication(state[i * 4 + 2], 3) ^
                         state[i * 4 + 3];
        tmp[i * 4 + 2] = state[i * 4] ^
                         state[i * 4 + 1] ^
                         galois_multiplication(state[i * 4 + 2], 2) ^
                         galois_multiplication(state[i * 4 + 3], 3);
        tmp[i * 4 + 3] = galois_multiplication(state[i * 4], 3) ^
                         state[i * 4 + 1] ^
                         state[i * 4 + 2] ^
                         galois_multiplication(state[i * 4 + 3], 2);
    }
    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

void cipher_our_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]) {
    unsigned char expandedKey[240];
    int num_rounds;
    if (key_size == 128) {
        num_rounds = 10;
    } else if (key_size == 192) {
        num_rounds = 12;
    } else if (key_size == 256) {
        num_rounds = 14;
    } else {
        printf("Invalid key size\n");
        return;
    }
    expandKey(expandedKey, key, key_size, (num_rounds + 1) * 16);
    printf("Expanded key:\n");
    for (int i = 0; i < (num_rounds + 1) * 16; i++) {
        printf("%02x ", expandedKey[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    addRoundKey(plaintext, expandedKey);
    for (int round = 1; round < num_rounds; round++) {
        subBytes(plaintext);
        shiftRows(plaintext);
        mixColumns(plaintext);
        addRoundKey(plaintext, expandedKey + round * 16);
    }
    subBytes(plaintext);
    shiftRows(plaintext);
    addRoundKey(plaintext, expandedKey + num_rounds * 16);
    for (int i = 0; i < 16; i++) {
        cipher[i] = plaintext[i];
    }
}
