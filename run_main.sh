gcc -o main main.c openssl_aes.c our_aes.c saes.c keys.c -lssl -lcrypto
./main 
