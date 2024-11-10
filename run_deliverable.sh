gcc -o encrypt encrypt.c openssl_aes.c our_aes.c saes.c saes_NI.c keys.c -lssl -lcrypto -maes -mpclmul -msse2
gcc -o decrypt decrypt.c openssl_aes.c our_aes.c saes.c saes_NI.c keys.c -lssl -lcrypto -maes -mpclmul -msse2
gcc -o speed_test speed.c openssl_aes.c our_aes.c saes.c saes_NI.c keys.c -lssl -lcrypto -maes -mpclmul -msse2