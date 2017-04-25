#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// This MUST be compiled using gcc -o Testencrypt Testencrypt.c -lssl -lcrypto

// This code is copied from https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-opensll/

#define KEYBITS 4096

int main (void)
{

  RSA *keypair;
  FILE *file;
  BIO *private;
  BIO *public;
  // http://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c-cross-platform
  if (access("Keys.txt", F_OK) != -1) {
    printf("Found keypair file!\n");
  } else {
    printf("Did not find keypair file. Generating new keypair...\n");

    private = BIO_new(BIO_s_mem());
    public = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(private, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(public, keypair);

    size_t pri_len = BIO_pending(private);
    size_t pub_len = BIO_pending(public);

    char *pri_key = malloc(pri_len + 1);
    char *pub_key = malloc(pub_len + 1);

    BIO_read(private, pri_key, pri_len);
    BIO_read(public, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    
    keypair = RSA_generate_key(KEYBITS, 3, NULL, NULL);

  }
  
  

  // Allocate memory for a message
  char message[KEYBITS/8];
  printf("Encrypt this: ");
  fgets(message, KEYBITS/8, stdin);
  message[strlen(message)-1] = '\0';

  char *encrypted_message = malloc(RSA_size(keypair));
  int encrypt_len;
  char *err = malloc(130);

  if((encrypt_len = RSA_public_encrypt(strlen(message)+1, (unsigned char*) message,
                                       (unsigned char*)encrypted_message, keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr, "Error encrypting message: %s\n", err);
  }


  
  char *decrypted_message = malloc(RSA_size(keypair));
  if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypted_message, (unsigned char*)decrypted_message,
                         keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(),err);
    fprintf(stderr, "Error decrypting message: %s\n", err);
  } else {
    printf("Decrypted message: %s\n", decrypted_message);
  }



  
  return 0;
}




