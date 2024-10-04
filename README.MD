## COMPILE
gcc -o main main.c openssl_aes.c our_aes.c saes.c -lssl -lcrypto

## RUN
./main 

## CHECK CIPHERS
https://paymentcardtools.com/basic-calculators/aes-calculator

## COMPILE test
gcc -o test test.c our_aes.c  -lssl -lcrypto

## RUN test
./test 