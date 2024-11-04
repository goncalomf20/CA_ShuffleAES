#ifndef OUR_AES_H
#define OUR_AES_H

void expandKey(unsigned char *expandedKey, unsigned char *key,  int key_size, int nr_key_chars);

void core(unsigned char *word, int iteration);

void rotate(unsigned char *word);


unsigned char getSBoxValue(unsigned char num);

unsigned char getSBoxValue(unsigned char num);

unsigned char getSBoxInvert(unsigned char num);

unsigned char getSBoxInvert(unsigned char num);


unsigned char getRconValue(unsigned char num);

unsigned char getRconValue(unsigned char num);
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

#endif