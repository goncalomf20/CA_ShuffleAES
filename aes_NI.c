#include <wmmintrin.h>
#include <stdint.h>
#include <stdio.h>

#define NUM_ROUNDS 10

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

void cipher(__m128i *plaintext, __m128i *round_keys) {
    __m128i x = *plaintext;
    x = _mm_xor_si128(x, round_keys[0]);
    for (int i = 1; i < NUM_ROUNDS; i++) {
        x = _mm_aesenc_si128(x, round_keys[i]);
    }
    x = _mm_aesenclast_si128(x, round_keys[NUM_ROUNDS]);
    *plaintext = x;
}

void decipher(__m128i *ciphertext, __m128i *round_keys) {
    __m128i x = *ciphertext;
    __m128i round_keys_dec[NUM_ROUNDS + 1];
    round_keys_dec[NUM_ROUNDS] = round_keys[NUM_ROUNDS];
    for (int i = NUM_ROUNDS - 1; i > 0; i--) {
        round_keys_dec[i] = _mm_aesimc_si128(round_keys[i]);
    }
    round_keys_dec[0] = round_keys[0];
    x = _mm_xor_si128(x, round_keys[NUM_ROUNDS]);
    for (int i = NUM_ROUNDS - 1; i > 0; i--) {
        x = _mm_aesdec_si128(x, round_keys_dec[i]);
    }
    x = _mm_aesdeclast_si128(x, round_keys_dec[0]);
    *ciphertext = x;
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

int main() {
    uint8_t key_bytes[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    __m128i key = _mm_loadu_si128((__m128i*)key_bytes);
    uint8_t plaintext_bytes[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                   0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    __m128i plaintext = _mm_loadu_si128((__m128i*)plaintext_bytes);
    printf("Original plaintext: ");
    for (int i = 0; i < 16; i++) printf("%02x ", plaintext_bytes[i]);
    printf("\n");
    __m128i round_keys[11];
    expand_key(&key, round_keys);
    cipher(&plaintext, round_keys);
    uint8_t encrypted_bytes[16];
    _mm_storeu_si128((__m128i*)encrypted_bytes, plaintext);
    printf("Encrypted: ");
    for (int i = 0; i < 16; i++) printf("%02x ", encrypted_bytes[i]);
    printf("\n");
    decipher(&plaintext, round_keys);
    uint8_t decrypted_bytes[16];
    _mm_storeu_si128((__m128i*)decrypted_bytes, plaintext);
    printf("Decrypted: ");
    for (int i = 0; i < 16; i++) printf("%02x ", decrypted_bytes[i]);
    printf("\n");
    int match = 1;
    for (int i = 0; i < 16; i++) {
        if (plaintext_bytes[i] != decrypted_bytes[i]) {
            match = 0;
            break;
        }
    }
    if (match) {
        printf("Decryption successful: Decrypted text matches the original plaintext.\n");
    } else {
        printf("Decryption failed: Decrypted text does not match the original plaintext.\n");
    }
    return 0;
}
