#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "our_aes.h"
#include <stdint.h>

unsigned char sboxoriginal[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};


// ------ Gerar a S-Sbox ------
void shuffle_sbox(unsigned char *sbox, unsigned char *key);
void invert_sbox(unsigned char *sbox, unsigned char *inverse_sbox);

// ------ Selecionar uma ronda ------
void select_round(unsigned char *SK,  unsigned int *selected_round);

// ------ Invert SSubBytes ------
void invSSubBytes(unsigned char *state, unsigned char *sbox);

// ... outras funções auxiliares
void areInverses(unsigned char *sbox, unsigned char *inverse_sbox);

// ------ AddRoundKey para a S-Round ------
void s_addRoundKey(unsigned char *state, unsigned char *roundKey , unsigned char *sk);
void getPseudoRandomPermo(unsigned char *roundKey , unsigned char *sk);


// ------ SubBytes para S-RoundKey ------
void s_subBytes(unsigned char *state, unsigned char *sbox);

void s_addRoundKey(unsigned char *state, unsigned char *roundKey , unsigned char *sk)
{
    for (int i = 0; i < 16; i++) {
        // XOR each byte of the round key with state
        // Use sk[i % 8] to repeat the 64-bit SK across 128 bits
        state[i] ^= roundKey[i] ^ sk[i % 8];
    }
}

void areInverses(unsigned char *sbox1, unsigned char *sbox2) {
    for (int x = 0; x < 256; x++) {
        // Check if sbox2[sbox1[x]] == x and sbox1[sbox2[x]] == x
        if (sbox2[sbox1[x]] != x || sbox1[sbox2[x]] != x) {
            printf("The S-Boxes are not inverses\n");
        }
    }
    printf("The Sbox are invertible\n"); // Passed all checks, they are inverses
}

void invSSubBytes(unsigned char *state,unsigned char *sbox)
{
    int i;
    /* substitute all the values from the state with the value in the SBox
     * using the state value as index for the SBox
     */
    for (i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

void getPseudoRandomPermo(unsigned char *roundKey, unsigned char *sk) {
    int roundKeyLength = 16;  // `roundKey` is 128 bits or 16 bytes
    int skLength = 8;         // `sk` is 8 bytes

    // Deterministic shuffle using only `sk`
    for (int i = roundKeyLength - 1; i > 0; i--) {
        // Use the current byte from `sk` as a rotation offset
        int j = sk[i % skLength] % (i + 1);  // Ensure j is within [0, i]

        // Swap bytes at indices i and j
        unsigned char temp = roundKey[i];
        roundKey[i] = roundKey[j];
        roundKey[j] = temp;
    }
}


void invert_sbox(unsigned char *sbox, unsigned char *inverse_sbox) {
    // Initialize the inverse_sbox to an invalid state
    memset(inverse_sbox, 0xFF, 256);  // Use 0xFF to signify uninitialized

    // Check if sbox is a valid permutation and invert it
    for (int i = 0; i < 256; i++) {
        unsigned char value = sbox[i];

        // Check if the value is within bounds and hasn't been assigned yet
        if (value >= 256 || inverse_sbox[value] != 0xFF) {
            // If invalid, we can either return or handle it as needed
            // Here, we can choose to just set inverse_sbox to an error state
            memset(inverse_sbox, 0xFF, 256);  // Reset inverse_sbox to indicate an error
            return;  // Exit the function
        }

        inverse_sbox[value] = i;  // Set the inverse mapping
    }
}

void select_round(unsigned char *SK, unsigned int *selected_round){
    unsigned char val = (SK[0] << 8) | SK[1];
    *selected_round = val % 10;
}

void s_subBytes(unsigned char *state, unsigned char *sbox)
{
    for (int i = 0; i < 16; i++) {
        // Use the S-Box to substitute each byte of the state
        state[i] = sbox[state[i]];
    }
}

// Fisher-Yates shuffle to generate a key-dependent S-Box
void shuffle_sbox(unsigned char *sbox, unsigned char *key) {
      // Create a seed based on the key bytes
    uint64_t seed = 0;
    for (int i = 0; i < 16 && i < 8; i++) {
        seed = (seed << 8) | key[i]; // Combine key bytes into a 64-bit seed
    }

    // Fisher-Yates shuffle, but with a deterministic sequence based on the seed
    for (int i = 255; i > 0; i--) {
        // Update seed to get a pseudo-random sequence
        seed = (seed * 6364136223846793005ULL + 1); // LCG parameters

        // Deterministically generate index j based on the seed
        int j = seed % (i + 1);

        // Swap elements at indices i and j
        unsigned char temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
    }
}


void cipher_saes(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]) {

    int rounds = (key_size == 16) ? 10 : (key_size == 24) ? 12 : 14;

    unsigned char s1[8];
    unsigned char s2[8];
    for (int i = 0; i < 8; i++) {
        s1[i] = sk[i];
        s2[i] = sk[i + 8];
    }


 

    unsigned int selected_round;
    select_round(s1,&selected_round);
    // printf("Selected round: %u\n", selected_round);

    // S-Box
    unsigned char ssbox[256];
    for (int i = 0; i < 256; i++) {
        ssbox[i] = sboxoriginal[i];
    }
    
    shuffle_sbox(ssbox, s2);
    // see if the shuffled sbox is at least 50% different from the original sbox
    int diff = 0;
    for (int i = 0; i < 256; i++) {
        if (ssbox[i] != sboxoriginal[i]) {
            diff++;
        }
    }

    // for (int i = 0; i < 256; i++) {
    //     printf("%02x ", ssbox[i]);
    //     if ((i + 1) % 16 == 0) {
    //         printf("\n");
    //     }
    // }

    int nr_key_chars = key_size * (rounds + 1) ;  // NR de characteres das Keys
    // 10 caracteres para as N rondas e mais um para a original

    unsigned char expandedKey[nr_key_chars];
    int i, j, k;

    // printf("**************************************************\n");
    // printf("*   Criar as %d keys necessárias  *\n", rounds);
    // printf("**************************************************\n");


    expandKey(expandedKey, key, key_size, nr_key_chars);
    

    // key scheduling
    // A primeira chave a ser usada não leva alterações  -> Key original (16 bytes)

    // printf("\n**************************************************\n");
    // printf("*   Começar Transformação inicial *\n");
    // printf("**************************************************\n");

    unsigned char roundKey[16];

    // Da primeira key -> 5b 5a 5a 5a 3e 3f 3f 3f 47 46 46 46 69 68 68 68
    //                     ^           ^           ^           ^
    // Usam-se os multiplos de 4 -> 5b 3e 47 69 para os primeiros 4 bytes
    // Depois usam se o seguinte de cada um posto anteriormente:
    // (5b) -> 5a , (3e) -> 3f , (47) -> 46 , (69) -> 68
    createRoundKey(expandedKey, roundKey);

     // the 128 bit block to encode
    unsigned char block[16];

    for (i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (j = 0; j < 4; j++)
            block[(i + (j * 4))] = plaintext[(i * 4) + j];
    }


    

    // printf("\n    Resultado antes da Transformação inicial:");
    // for (i = 0; i < 16; i++)
    // {
    //     printf(" %02x ",block[i]);

    // }

    getPseudoRandomPermo(s1,roundKey);
 
        
    addRoundKey(block, roundKey);


    // printf("\n    Resultado da  Transformação inicial:");
    // for (i = 0; i < 16; i++)
    // {
    //     printf(" %02x ",block[i]);

    // }

    // printf("\n**************************************************\n");
    // printf("*   Começar as %d rondas *\n", rounds);
    // printf("**************************************************\n");

    for (int i = 1; i < rounds; i++) {
        // printf("\n        --- Ronda %d --- \n", i);


        createRoundKey(expandedKey + 16 * i, roundKey);
        // printf("bloco: %d " , i);
        // print_hex(block, 16);
        
        // printf("    Key que vai ser usada:");

        // for (j = 0; j < 16; j++)
        // {
        //     printf(" %02x ",roundKey[j]);

        // }
        // printf("\n");


        if (i == selected_round) {
            
         

            s_subBytes(block, ssbox);
            shiftRows(block);
            mixColumns(block);
            getPseudoRandomPermo(s1,roundKey);

           
    
            s_addRoundKey(block, roundKey, sk);
        } else {
            subBytes(block);
            shiftRows(block);
            mixColumns(block);
            getPseudoRandomPermo(s1,roundKey);
            addRoundKey(block, roundKey);
        }

     


    }

    // printf("\n        --- Ronda %d --- \n", rounds);


    createRoundKey(expandedKey + 16 * rounds, roundKey);

    // printf("    Key que vai ser usada:");

    // for (j = 0; j < 16; j++)
    // {
    //     printf(" %02x ",roundKey[j]);

            

    // }
    // printf("\n");

    

    subBytes(block);
    shiftRows(block);
 
    print_hex(block, 16);
    getPseudoRandomPermo(s1,roundKey);


    addRoundKey(block, roundKey);

    // printf("    Resultado da ronda %d: ", rounds);
    // for (i = 0; i < 16; i++)
    // {
    //     printf(" %02x ",block[i]);
    // }
    // printf("\n");

    for (i = 0; i < 4; i++)
    {

        for (j = 0; j < 4; j++)
            cipher[(i * 4) + j] = block[(i + (j * 4))];
    }

    // printf("\n\n--> Resultado da final : " );
    // for (i = 0; i < 16; i++)
    // {
    //     printf(" %02x ",cipher[i]);
    // }
    // printf("\n");

}

void decipher_saes(unsigned char key[], unsigned char decipheredtext[16], int key_size, unsigned char cipher[16] , unsigned char sk[16])
{
    unsigned char block[16];
    int rounds = 10;
    int nr_key_chars = key_size * (rounds + 1) ;  // NR de characteres das Keys
    // 10 caracteres para as N rondas e mais um para a original

    unsigned char s1[8];
    unsigned char s2[8];
    for (int i = 0; i < 8; i++) {
        s1[i] = sk[i];
        s2[i] = sk[i + 8];
    }

   


    unsigned char inv_sbox[256];
    unsigned char Ss_box[256];
    for (int i = 0; i < 256; i++) {
        Ss_box[i] = sboxoriginal[i];
    }
    
    shuffle_sbox(Ss_box, s2);
    
    invert_sbox(Ss_box, inv_sbox);

    // for (int i = 0; i < 256; i++) {
    //     printf("%02x ", Ss_box[i]);
        
    // }

    unsigned int result;
    // areInverses(Ss_box, inv_sbox);


    unsigned int selected_round;
    select_round(s1,&selected_round);
    // printf("Selected round: %u\n", selected_round);

    int i, j;
    unsigned char expandedKeyS[nr_key_chars];
    unsigned char roundKey[16];

    // for (i = 0; i < 16; i++)
    // {
    //     printf("%2.2x", key[i]);
    // }
    // printf("\n");


    expandKey(expandedKeyS, key, key_size, nr_key_chars);



    // printf("**************************************************\n");
    // printf("*   Começar a decifrar  *\n");
    // printf("**************************************************\n");

    // // print the expanded key
    


    for (i = 0; i < 4; i++)
    {
        
        for (j = 0; j < 4; j++)
            block[(i * 4) + j] = cipher[(i + (j * 4))];
    }
    
    // printf("\n        --- Ronda %d (Só XOR com key)--- \n", rounds);
    
    createRoundKey(expandedKeyS + 16 * rounds, roundKey);
    // printf("    Key que vai ser usada:");
    // print_hex(roundKey, 16);
        
  
    getPseudoRandomPermo(s1,roundKey);
  
    addRoundKey(block, roundKey);
    invShiftRows(block);
    invSubBytes(block);



    for (i = rounds - 1; i > 0; i--){
        // printf("\n        --- Ronda %d --- \n", i);
        createRoundKey(expandedKeyS + 16 * i, roundKey);

        // printf("    Key que vai ser usada:");
        // print_hex(roundKey, 16);
        
        // printf("    Antes:");

        // print_hex(block, 16);

        if (selected_round == i){
            s_addRoundKey(block, roundKey, sk);
            

            invMixColumns(block);
            invShiftRows(block);
            invSSubBytes(block, inv_sbox);

           
        } else {
            addRoundKey(block, roundKey);
            invMixColumns(block);
            invShiftRows(block);
            invSubBytes(block);

           
        }
    }

    createRoundKey(expandedKeyS, roundKey);
   
    addRoundKey(block, roundKey);

    for (i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (j = 0; j < 4; j++)
            decipheredtext[(i * 4) + j] = block[(i + (j * 4))];
    }


}