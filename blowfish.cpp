#include <openssl/blowfish.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>

#define DATA_LENGTH 8
#define KEY_LENGTH 8

int main()
{
    unsigned char keyStr[KEY_LENGTH];
    unsigned char in[DATA_LENGTH] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    unsigned char out[DATA_LENGTH];

    read(0, keyStr, 8);
    BF_KEY *key = (BF_KEY*)malloc(sizeof(BF_KEY));
    BF_set_key(key, KEY_LENGTH, keyStr);
    BF_ecb_encrypt(in, out, key, BF_ENCRYPT);
    std::cout << out << std::endl;
}