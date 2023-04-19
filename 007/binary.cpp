#include <unistd.h>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <iostream>

/**
 * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];
  
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = (unsigned char*) malloc(p_len);\
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

int main(int argc, char **argv)
{
  /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
     status of enc/dec operations */
  EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();

  /* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte 
     integers on the stack as 64 bits of contigous salt material - 
     ofcourse this only works if sizeof(int) >= 4 */
  unsigned int salt[] = {12345, 54321};
  unsigned char key_data[1];
  int key_data_len = 1;
  read(0, key_data, key_data_len);
  int i;
  int len = 16;
  char input[16] = {'[', '=', '�', 'r', '&', '�', '�', '', 'Y', '�', '', '�', '&', '�', '�', '\\'};
  
  /* gen key and iv. init the cipher ctx object */
  if (aes_init(key_data, key_data_len, (unsigned char *)&salt, en, de)) {
    return -1;
  }
  
  std::cout << (char *)aes_decrypt(de, (unsigned char *)input, &len) << std::endl;

  EVP_CIPHER_CTX_free(en);
  EVP_CIPHER_CTX_free(de);
  return 0;
}