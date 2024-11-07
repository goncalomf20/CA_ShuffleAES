#include <wmmintrin.h>
#include <stdint.h>
#include <stdio.h>

unsigned char sboxoriginalNI[256] = {
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

void InvMixColumnsNI(__m128i *state);
void InvShiftRowsNI(__m128i *state);

void InvSSubBytesNI(__m128i *state, unsigned char *sbox);

__m128i get_round_key(__m128i key, __m128i index) {
    __m128i tmp;
    index = _mm_shuffle_epi32(index, 0xff);
    tmp = _mm_slli_si128(key, 0x4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(tmp, 0x4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(tmp, 0x4);
    key = _mm_xor_si128(key, tmp);
    key = _mm_xor_si128(key, index);
    return key;
}

void expand_key(__m128i *key, __m128i *round_keys) {
    round_keys[0] = *key;
    round_keys[1] = get_round_key(round_keys[0], _mm_aeskeygenassist_si128(round_keys[0], 0x01));
    round_keys[2] = get_round_key(round_keys[1], _mm_aeskeygenassist_si128(round_keys[1], 0x02));
    round_keys[3] = get_round_key(round_keys[2], _mm_aeskeygenassist_si128(round_keys[2], 0x04));
    round_keys[4] = get_round_key(round_keys[3], _mm_aeskeygenassist_si128(round_keys[3], 0x08));
    round_keys[5] = get_round_key(round_keys[4], _mm_aeskeygenassist_si128(round_keys[4], 0x10));
    round_keys[6] = get_round_key(round_keys[5], _mm_aeskeygenassist_si128(round_keys[5], 0x20));
    round_keys[7] = get_round_key(round_keys[6], _mm_aeskeygenassist_si128(round_keys[6], 0x40));
    round_keys[8] = get_round_key(round_keys[7], _mm_aeskeygenassist_si128(round_keys[7], 0x80));
    round_keys[9] = get_round_key(round_keys[8], _mm_aeskeygenassist_si128(round_keys[8], 0x1B));
    round_keys[10] = get_round_key(round_keys[9], _mm_aeskeygenassist_si128(round_keys[9], 0x36));
}

void getPseudoRandomPermoNI(__m128i sk, __m128i *roundKey) {
    unsigned char sk_bytes[8];  // Only use the first 64 bits (8 bytes) of sk
    unsigned char roundKey_bytes[16];

    // Store the first 64 bits of __m128i sk into byte array
    _mm_storel_epi64((__m128i*)sk_bytes, sk);
    _mm_storeu_si128((__m128i*)roundKey_bytes, *roundKey);

    int roundKeyLength = 16;  // `roundKey` is 128 bits or 16 bytes
    int skLength = 8;         // Only using the first 64 bits or 8 bytes of `sk`

    // Deterministic shuffle using only the first 64 bits of `sk`
    for (int i = roundKeyLength - 1; i > 0; i--) {
        // Use the current byte from `sk` as a rotation offset
        int j = sk_bytes[i % skLength] % (i + 1);  // Ensure j is within [0, i]

        // Swap bytes at indices i and j
        unsigned char temp = roundKey_bytes[i];
        roundKey_bytes[i] = roundKey_bytes[j];
        roundKey_bytes[j] = temp;
    }

    // Store the shuffled bytes back into the __m128i roundKey
    *roundKey = _mm_loadu_si128((__m128i*)roundKey_bytes);
}


void InvMixColumnsNI(__m128i *state)
{
    unsigned char *char_state = (char *)state;
    invMixColumns(char_state);

    *state = _mm_loadu_si128((__m128i*)char_state);  
}

void InvShiftRowsNI(__m128i *state)
{

    unsigned char *char_state = (char *)state;
    invShiftRows(char_state);

    *state = _mm_loadu_si128((__m128i*)char_state);  
}

void s_subBytesNI(__m128i *state, unsigned char *sbox)
{
    
    // unsigned char state_bytes[16];
    // _mm_storeu_si128((__m128i*)state_bytes, *state);

    // for (int i = 0; i < 16; i++) {
    //     state_bytes[i] = sbox[state_bytes[i]];
    // }

    // *state = _mm_loadu_si128((__m128i*)state_bytes);

    unsigned char *char_state = (char *)state;
  
  
    s_subBytes(char_state, sbox);

    *state = _mm_loadu_si128((__m128i*)char_state);   
}

void shiftRowsNI(__m128i *state)
{
    unsigned char *char_state = (char *)state;
    shiftRows(char_state);

    *state = _mm_loadu_si128((__m128i*)char_state);    

}

void mixColumnsNI(__m128i *state) {

    unsigned char *char_state = (char *)state;
  
  
    mixColumns(char_state);

    *state = _mm_loadu_si128((__m128i*)char_state);    
}

void InvSSubBytesNI(__m128i *state, unsigned char *sbox)
{

    unsigned char *char_state = (char *)state;
  
  
    invSSubBytes(char_state, sbox);

    *state = _mm_loadu_si128((__m128i*)char_state);   
}

void InvSubBytesNI(__m128i *state)
{

    unsigned char *char_state = (char *)state;
  
  
    invSubBytes(char_state);

    *state = _mm_loadu_si128((__m128i*)char_state);   
}

void Round_block(__m128i *block) {
    // Store the contents of `*roundKey` into an intermediate array for reordering
    unsigned char temp[16];
    _mm_storeu_si128((__m128i *)temp, *block);

    // Perform the transposition to match the original function's behavior
    unsigned char transposed[16];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            transposed[i * 4 + j] = temp[j * 4 + i];
        }
    }

    // Store the transposed result back into `*roundKey`
    *block = _mm_loadu_si128((__m128i *)transposed);
}

void s_addRoundKeyNI(__m128i *state, __m128i *roundKey , __m128i *sk)
{

    unsigned char *char_state = (char *)state;
    unsigned char *char_sk = (char *)sk;
    unsigned char *char_roundKey = (char *)roundKey;

  
  
    s_addRoundKey(char_state, char_roundKey, char_sk);

    *state = _mm_loadu_si128((__m128i*)char_state);   
}


void print_m128i(__m128i var) {
    // Create a temporary array to hold the 128-bit value as bytes
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, var);

    // Print each byte in hexadecimal format
    for (int i = 0; i < 16; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}
void print_sbox(const unsigned char *sbox) {
    printf("Ss_box:\n");
    for (int i = 0; i < 256; i++) {
        printf("%02x ", sbox[i]);
        // Print 16 values per line for readability
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
}

void cipher_saesNI(unsigned char key[16], unsigned char sk[16], unsigned char plaintext[16], int key_size, unsigned char cipher[16]) {

    unsigned int selected_round;
    unsigned char s1[8];
    unsigned char s2[8];
    for (int i = 0; i < 8; i++) {
        s1[i] = sk[i];
        s2[i] = sk[i + 8];
    }
        // S-Box
    unsigned char ssbox[256];
    for (int i = 0; i < 256; i++) {
        ssbox[i] = sboxoriginalNI[i];
    }

       
    shuffle_sbox(ssbox, s2);

    // see if the shuffled sbox is at least 50% different from the original sbox
    int diff = 0;
    for (int i = 0; i < 256; i++) {
        if (ssbox[i] != sboxoriginalNI[i]) {
            diff++;
        }
    }

    // print_sbox(ssbox);

    __m128i key128 = _mm_loadu_si128((__m128i*)key);
    __m128i sk128 = _mm_loadu_si128((__m128i*)sk);
    __m128i plaintext128 = _mm_loadu_si128((__m128i*)plaintext);

    __m128i round_keys[11];
    expand_key(&key128, round_keys);

    select_round(s1,&selected_round);
    // printf("Selected round ni: %u\n", selected_round);

    __m128i x = plaintext128;
    Round_block(&round_keys[0]);
    getPseudoRandomPermoNI(sk128, &round_keys[0]);   
    Round_block(&round_keys[0]);

    // printf("    key 0: ");
    // print_m128i(round_keys[0]);

    x = _mm_xor_si128(x, round_keys[0]);

    // printf("    bloco 0: ");
    // print_m128i(x);


    for (int i = 1; i < 10; i++) {

        Round_block(&round_keys[i]);
        getPseudoRandomPermoNI(sk128,&round_keys[i]);
        Round_block(&round_keys[i]);

        // printf("\n    key %d: ", i);
        // print_m128i(round_keys[i]);

        if (i == selected_round) {

            Round_block(&round_keys[i]);            
            Round_block(&x); 

            s_subBytesNI(&x, ssbox);
        
            shiftRowsNI(&x);
            
            mixColumnsNI(&x);

            s_addRoundKeyNI(&x, &round_keys[i], &sk128);

            Round_block(&x);


        } else {  
           
            x = _mm_aesenc_si128(x, round_keys[i]);

        }

        // printf("    block %d: ", i);
        // print_m128i(x);

    }

    Round_block(&round_keys[10]);
    getPseudoRandomPermoNI(sk128,&round_keys[10]);
    Round_block(&round_keys[10]);

    // printf("\n    key 10: ");
    // print_m128i(round_keys[10]);

    x = _mm_aesenclast_si128(x, round_keys[10]);

    // printf("    bloco 10: ");
    // print_m128i(x);


    _mm_storeu_si128((__m128i*)cipher, x);
}

void decipher_saesNI(unsigned char key[16], unsigned char sk[16], unsigned char ciphertext[16], int key_size, unsigned char plaintext[16]) {
    unsigned int selected_round;
    unsigned char s1[8], s2[8];

    // Split `sk` into two parts
    for (int i = 0; i < 8; i++) {
        s1[i] = sk[i];
        s2[i] = sk[i + 8];
    }

    // Initialize S-Box and inverse S-Box
    unsigned char inv_sbox[256], Ss_box[256];
    for (int i = 0; i < 256; i++) {
        Ss_box[i] = sboxoriginalNI[i];
    }

    shuffle_sbox(Ss_box, s2);
    invert_sbox(Ss_box, inv_sbox);
   
    // Load key and ciphertext into 128-bit registers
    __m128i key128 = _mm_loadu_si128((__m128i*)key);
    __m128i sk128 = _mm_loadu_si128((__m128i*)sk);
    __m128i round_keys[11];

    // Key expansion
    expand_key(&key128, round_keys);
    select_round(s1, &selected_round);

    // // // Start decryption
    __m128i x = _mm_loadu_si128((__m128i*)ciphertext);

    Round_block(&round_keys[10]);
    getPseudoRandomPermoNI(sk128,&round_keys[10]);
    Round_block(&round_keys[10]);

    // printf("    key 10: ");
    // print_m128i(round_keys[10]);    
    
    x = _mm_xor_si128(x, round_keys[10]);


    // printf("    bloco 10: ");
    // print_m128i(x); 
   
    for (int i = 9; i > 0; i--) {

        Round_block(&round_keys[i]);
        getPseudoRandomPermoNI(sk128,&round_keys[i]);
        Round_block(&round_keys[i]);

        // printf("\n    key %d: ", i);
        // print_m128i(round_keys[i]);

        if (i == selected_round) {
            Round_block(&x);   
            
            InvShiftRowsNI(&x);
            InvSubBytesNI(&x);
            
            Round_block(&round_keys[i]);
           
            
            s_addRoundKeyNI(&x, &round_keys[i], &sk128);

            InvMixColumnsNI(&x);
            
            InvShiftRowsNI(&x);
            
            InvSSubBytesNI(&x, inv_sbox);
            
            __m128i t = _mm_loadu_si128(&round_keys[i-1]);
            Round_block(&t);
            getPseudoRandomPermoNI(sk128,&t);


            // printf("    suposta key %d: ", i-1);
            // print_m128i(t);

            if (i - 1 == 0 ){
                x = _mm_xor_si128(x, t);

            }else {
                x = _mm_xor_si128(x, t);
                InvMixColumnsNI(&x);
            
            }
            
            Round_block(&x);

        } else {
    
            if (i == selected_round -1 ) {
                continue;
            }

            x = _mm_aesdec_si128(x,  _mm_aesimc_si128(round_keys[i]));
          
        }
        

        
    }

    if (selected_round != 1){

        Round_block(&round_keys[0]);
        getPseudoRandomPermoNI(sk128, &round_keys[0]);   
        Round_block(&round_keys[0]);

        x = _mm_aesdeclast_si128(x, round_keys[0]);
     
    }
   
    // // //Store the result  
    _mm_storeu_si128((__m128i*)plaintext, x);
}

