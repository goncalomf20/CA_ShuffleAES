#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "our_aes.h"



unsigned char sbox[256] = {
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

// Implementation: Rcon
unsigned char Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
    0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};



unsigned char rsbox[256] =
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

void expandKey(unsigned char *expandedKey, unsigned char *key,  int key_size, int nr_key_chars);

void core(unsigned char *word, int iteration);

void rotate(unsigned char *word);


unsigned char getSBoxValue(unsigned char num);

unsigned char getSBoxValue(unsigned char num)
{
    return sbox[num];
}

unsigned char getSBoxInvert(unsigned char num);

unsigned char getSBoxInvert(unsigned char num)
{
    return rsbox[num];
}


unsigned char getRconValue(unsigned char num);

unsigned char getRconValue(unsigned char num)
{
    return Rcon[num];
}

// ------ Cifrar Rondas ------
//Substitute bytes
void subBytes(unsigned char *state);

// addRound Key
void addRoundKey(unsigned char *state, unsigned char *roundKey);

// shiftRows
void shiftRows(unsigned char *state);
void shiftRow(unsigned char *state, unsigned char nbr);

// mixColumns
void mixColumns(unsigned char *column);
void mixColumn(unsigned char *column);
unsigned char galois_multiplication(unsigned char a, unsigned char b);

// ------ Decifrar Rondas ------
void invSubBytes(unsigned char *state);
void invShiftRows(unsigned char *state);
void invShiftRow(unsigned char *state, unsigned char nbr);
void invMixColumns(unsigned char *state);
void invMixColumn(unsigned char *column);

void invSubBytes(unsigned char *state)
{
    int i;
    /* substitute all the values from the state with the value in the SBox
     * using the state value as index for the SBox
     */
    for (i = 0; i < 16; i++)
        state[i] = getSBoxInvert(state[i]);
}

void invShiftRows(unsigned char *state)
{
    int i;
    // iterate over the 4 rows and call invShiftRow() with that row
    for (i = 0; i < 4; i++)
        invShiftRow(state + i * 4, i);
}

void invShiftRow(unsigned char *state, unsigned char nbr)
{
    int i, j;
    unsigned char tmp;
    // each iteration shifts the row to the right by 1
    for (i = 0; i < nbr; i++)
    {
        tmp = state[3];
        for (j = 3; j > 0; j--)
            state[j] = state[j - 1];
        state[0] = tmp;
    }
}
void invMixColumns(unsigned char *state)
{
    int i, j;
    unsigned char column[4];

    // iterate over the 4 columns
    for (i = 0; i < 4; i++)
    {
        // construct one column by iterating over the 4 rows
        for (j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }
        // apply the invMixColumn on one column
        invMixColumn(column);

        // put the values back into the state
        for (j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
        }
    }
}

void invMixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    int i;
    for (i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_multiplication(cpy[0], 14) ^
                galois_multiplication(cpy[3], 9) ^
                galois_multiplication(cpy[2], 13) ^
                galois_multiplication(cpy[1], 11);
    column[1] = galois_multiplication(cpy[1], 14) ^
                galois_multiplication(cpy[0], 9) ^
                galois_multiplication(cpy[3], 13) ^
                galois_multiplication(cpy[2], 11);
    column[2] = galois_multiplication(cpy[2], 14) ^
                galois_multiplication(cpy[1], 9) ^
                galois_multiplication(cpy[0], 13) ^
                galois_multiplication(cpy[3], 11);
    column[3] = galois_multiplication(cpy[3], 14) ^
                galois_multiplication(cpy[2], 9) ^
                galois_multiplication(cpy[1], 13) ^
                galois_multiplication(cpy[0], 11);
}

unsigned char galois_multiplication(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    unsigned char counter;
    unsigned char hi_bit_set;
    for (counter = 0; counter < 8; counter++)
    {
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

void mixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    int i;
    for (i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_multiplication(cpy[0], 2) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 3);

    column[1] = galois_multiplication(cpy[1], 2) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 3);

    column[2] = galois_multiplication(cpy[2], 2) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 3);

    column[3] = galois_multiplication(cpy[3], 2) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 3);
}


void mixColumns(unsigned char *state)
{
    int i, j;
    unsigned char column[4];

    // iterate over the 4 columns
    for (i = 0; i < 4; i++)
    {
        // construct one column by iterating over the 4 rows
        for (j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }


        // apply the mixColumn on one column
        mixColumn(column);

        // put the values back into the state
        for (j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
        }

    }
}



// Cada linha dá shift para a esquerda nbr vezes
void shiftRow(unsigned char *state, unsigned char nbr)
{
    int i, j;
    unsigned char tmp;
    for (i = 0; i < nbr; i++)
    {
        tmp = state[0];
        for (j = 0; j < 3; j++)
            state[j] = state[j + 1];
        state[3] = tmp;
    }
}

// Cada linha chama a função shiftRow
void shiftRows(unsigned char *state)
{
    int i;

    for (i = 0; i < 4; i++) {

      
        shiftRow(state + i * 4, i);
    

    }
}

// Usa a SBox a partir do hex de cada byte -> ex: 3c
void subBytes(unsigned char *state)
{
    int i;
    for (i = 0; i < 16; i++) {

        state[i] = getSBoxValue(state[i]);

    }
      

}

// Só um XOR
void addRoundKey(unsigned char *state, unsigned char *roundKey)
{
    int i;
    for (i = 0; i < 16; i++)
        state[i] = state[i] ^ roundKey[i];
}

void core(unsigned char *word, int iteration)
{
    int i;

    // rotate the 32-bit word 8 bits to the left
    rotate(word);

    // apply S-Box substitution on all 4 parts of the 32-bit word
    for (i = 0; i < 4; ++i)
    {
        word[i] = getSBoxValue(word[i]);
    }

    // XOR the output of the rcon operation with i to the first part (leftmost) only
    word[0] = word[0] ^ getRconValue(iteration);
}

void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey);


// Shift 8 bits (1 byte) to the left
// rotate(1d 2c 3a 4f) = 2c 3a 4f 1d
void rotate(unsigned char *word)
{
    unsigned char c;
    int i;

    c = word[0];
    for (i = 0; i < 3; i++)
        word[i] = word[i + 1];
    word[3] = c;
}

void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey)
{
    int i, j;
    // iterate over the columns
    for (i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (j = 0; j < 4; j++)
            roundKey[(i + (j * 4))] = expandedKey[(i * 4) + j];
    }
}




void cipher_our_aes(unsigned char key[], unsigned char plaintext[16], int key_size, unsigned char cipher[16]) {

    int rounds = (key_size == 16) ? 10 : (key_size == 24) ? 12 : 14;

    int nr_key_chars = key_size * (rounds + 1) ;  // NR de characteres das Keys
    // 10 caracteres para as N rondas e mais um para a original

    unsigned char expandedKey[nr_key_chars];
    int i, j, k;

    // printf("**************************************************\n");
    // printf("*   Criar as %d keys necessárias  *\n", rounds);
    // printf("**************************************************\n");


    expandKey(expandedKey, key, key_size, nr_key_chars);

    // for (i = 0; i < nr_key_chars; i++)
    // {
    //     printf("%2.2x%c", expandedKey[i], ((i + 1) % key_size) ? ' ' : '\n');
    // }
    

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


    // printf("    Key que vai ser usada:");
    // for (i = 0; i < 16; i++)
    // {
    //     printf(" %02x ",roundKey[i]);

    // }

    // printf("\n    Resultado antes da Transformação inicial:");
    // for (i = 0; i < 16; i++)
    // {
    //     printf(" %02x ",block[i]);

    // }


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


        // Somar ao endereço de expandedKey 16 * i 
        // Para excluir as keys que ja foram usadas
        createRoundKey(expandedKey + 16 * i, roundKey);
        
        // printf("    Key que vai ser usada:");

        // for (j = 0; j < 16; j++)
        // {
        //     printf(" %02x ",roundKey[j]);

            

        // }
        // printf("\n");

        // Composição de uma ronda
        subBytes(block);
        shiftRows(block);
        mixColumns(block);
        addRoundKey(block, roundKey);

        // printf("    Resultado da ronda %d:", i);
        // for (k = 0; k < 16; k++)
        // {
        //     printf(" %02x ",block[k]);

        // }


    }
    
    // last round -> Usa a última Key das 10 ou 12 ou 14
   // Úlima ronda só tem subBytes, shiftRows e addRoundKey
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
    addRoundKey(block, roundKey);

    // printf("    Resultado da ronda %d: ", rounds);
    // for (i = 0; i < 16; i++)
    // {
    //     printf(" %02x ",block[i]);
    // }
    // printf("\n");

    for (i = 0; i < 4; i++)
    {
        // iterate over the rows
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

void decipher_our_aes(unsigned char key[], unsigned char decipheredtext[16], int key_size, unsigned char cipher[16])
{
    unsigned char block[16];
    int rounds = (key_size == 16) ? 10 : (key_size == 24) ? 12 : 14;
    int nr_key_chars = key_size * (rounds + 1) ;  // NR de characteres das Keys
    // 10 caracteres para as N rondas e mais um para a original

    int i, j;
    unsigned char expandedKey[nr_key_chars];
    unsigned char roundKey[16];


    expandKey(expandedKey, key, key_size, nr_key_chars);

    // for (i = 0; i < nr_key_chars; i++)
    // {
    //     printf("%2.2x%c", expandedKey[i], ((i + 1) % key_size) ? ' ' : '\n');
    // }



    // printf("**************************************************\n");
    // printf("*   Começar a decifrar  *\n");
    // printf("**************************************************\n");

    // print_hex(cipher, 16);

    for (i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (j = 0; j < 4; j++)
            block[(i * 4) + j] = cipher[(i + (j * 4))];
    }
    
    // printf("\n        --- Ronda %d (Só XOR com key)--- \n", rounds);
    
    createRoundKey(expandedKey + 16 * rounds, roundKey);
    // printf("    Key que vai ser usada:");
    // print_hex(roundKey, 16);
        
    // printf("    Antes:");

    // print_hex(block, 16);
    addRoundKey(block, roundKey);

    
    // printf("    Resultado da ronda %d: ", rounds);
    // print_hex(block, 16);


    for (i = rounds - 1; i > 0; i--){
        // printf("\n        --- Ronda %d --- \n", i);
        createRoundKey(expandedKey + 16 * i, roundKey);

        // printf("    Key que vai ser usada:");
        // print_hex(roundKey, 16);
        
        // printf("    Antes:");

        // print_hex(block, 16);


        invShiftRows(block);
        invSubBytes(block);
        addRoundKey(block, roundKey);
        invMixColumns(block);

        // printf("    Resultado da ronda %d:", i);
        // print_hex(block, 16);


    }

    createRoundKey(expandedKey, roundKey);
    invShiftRows(block);
    invSubBytes(block);
    addRoundKey(block, roundKey);

    for (i = 0; i < 4; i++)
    {
        // iterate over the rows
        for (j = 0; j < 4; j++)
            decipheredtext[(i * 4) + j] = block[(i + (j * 4))];
    }

    // printf("\n    Resultado final:");
    // print_hex(decipheredtext, 16);



}


void expandKey(unsigned char *expandedKey, 
               unsigned char *key,  
               int key_size, 
               int nr_key_chars)
{

    int currentSize = key_size;
    int rconIteration = 1;

    unsigned char t[4] = {0}; // temporary 4-byte variable
    int i;

    for (i = 0; i < key_size; i++)
        expandedKey[i] = key[i];

    while (currentSize < nr_key_chars)
    {   
        
        
        // printf("\n t inical para a geração da keys [%d, .. %d]: \n  ", currentSize, currentSize+4);
        
        // Editar a variavel t para os últimos 4 bytes formados
        for (i = 0; i < 4; i++)
        {

            t[i] = expandedKey[(currentSize - 4) + i];
            // printf("  %d ", (currentSize - 4) + i); // Print t[i]
        }
        // printf("\n");


        // Em todos 16, 32, 48, 64, 80, ... bytes
        // O t vai sofrer alteraçes
        if (currentSize % key_size == 0)
        {

            // printf("   --> t sofre grande alteração (%d) (iterationRcon %d)\n" , currentSize, rconIteration );
            // usa se o rconIteration e só depois é incrementado
            core(t, rconIteration++);
        }

        if (key_size == 32 && ((currentSize % key_size) == 16))
        {
            for (i = 0; i < 4; i++)
                t[i] = getSBoxValue(t[i]);
        }


        // Atualizar os 4 bytes seguintes
        for (i = 0; i < 4; i++)
        {
            // printf("       Criada a key nr: %d usando -> nr: %d XOR t[%d] \n",currentSize,  currentSize - key_size, i);
            expandedKey[currentSize] = expandedKey[currentSize - key_size] ^ t[i];
            // printf("          Valor: 0x%02x\n",expandedKey[currentSize]); // Print t[i] as a hexadecimal value
            currentSize++;

        }

        // printf("\n");


    }

    //print the expanded key
    // for (i = 0; i < nr_key_chars; i++)
    // {
    //     printf("%2.2x%c", expandedKey[i], ((i + 1) % key_size) ? ' ' : '\n');
    // }


}
