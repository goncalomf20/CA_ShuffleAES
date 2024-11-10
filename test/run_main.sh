gcc -o main main.c openssl_aes.c our_aes.c saes.c saes_NI.c keys.c -lssl -lcrypto -maes -mpclmul -msse2
./main 
