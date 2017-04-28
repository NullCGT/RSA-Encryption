#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// This MUST be compiled using gcc -o Testencrypt Testencrypt.c -lssl -lcrypto

// This code is copied from https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-opensll/

#define KEYBITS 4096
#define PUBFILENAME "PUBKEY.pem"
#define PRIVFILENAME "PRIVKEY.pem"
// http://stackoverflow.com/questions/3585846/color-text-in-terminal-applications-in-unix
#define CYAN "\x1B[36m"
#define GREEN "\x1B[32m"
#define RED "\x1B[31m"
#define RESET "\x1B[0m"

int main (void)
{

  RSA *keypair;
  FILE *file;
  BIO *private;
  BIO *public;
  char* pri_key;
  char* pub_key;
  RSA **pubkey;
  RSA **privkey;

  OpenSSL_add_all_algorithms();
  system("clear");
  // http://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c-cross-platform
  if (access(PUBFILENAME, F_OK) != -1 && access(PRIVFILENAME, F_OK) != -1) {
    printf("Found keypair file!\n");
    
    file = fopen(PUBFILENAME, "w");
    PEM_read_RSA_PUBKEY(file,pubkey,NULL,NULL);
    fclose(file);
    file = fopen(PRIVFILENAME,"w");
    PEM_read_RSAPrivateKey(file,privkey,NULL,NULL);
    fclose(file);
    
  } else {
    printf("Did not find keypair file. Generating new keypair...\n");
    keypair = RSA_generate_key(KEYBITS, 3, NULL, NULL);
    private = BIO_new(BIO_s_mem());
    public = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(private, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(public, keypair);

    size_t pri_len = BIO_pending(private);
    size_t pub_len = BIO_pending(public);

    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);

    BIO_read(private, pri_key, pri_len);
    BIO_read(public, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    

    file = fopen(PUBFILENAME, "w");
    PEM_write_RSA_PUBKEY(file, keypair);
    fclose(file);
    file = fopen(PRIVFILENAME,"w");
    PEM_write_RSAPrivateKey(file,keypair,NULL,NULL,0,NULL,NULL);
    fclose(file);
  }

  // Welcome messages
  printf("Welcome to the secure messanger client.\n");
  printf("When you message someone else, your message will be sent securely over a server relay.\n");
  printf(CYAN "Messages you have sent are displayed in cyan.\n" RESET);
  printf(GREEN "Messages you receive are displayed in green.\n" RESET);
  printf("Type :help for help.\n\n");
  

  // Allocate memory for a message
  while(1 == 1) {
    char message[KEYBITS/8];
    fgets(message, KEYBITS/8, stdin);
    message[strlen(message)-1] = '\0';

    if (strcmp(message, ":logout") == 0) {
      printf("Logging out...\n");
      system("clear");
      return 0;
    } else if (strcmp(message, ":help") == 0) {
      printf("\nCommands:"
             "\n:logout     Quits the program.\n"
             ":help       Displays command list.\n"
             ":public     Prints your public key to the console.\n\n");
    }
    else if (strcmp(message, ":public") == 0) {
        printf("\n%s\n\n", pub_key);
    }
    else {

      char *encrypted_message = malloc(RSA_size(keypair));
      int encrypt_len;
      char *err = malloc(130);

      if((encrypt_len = RSA_public_encrypt(strlen(message)+1, (unsigned char*) message,
                                           (unsigned char*)encrypted_message, keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr,RED "Error encrypting message: %s\n" RESET, err);
      } else {
        printf(CYAN "%s\n" RESET, message);
      }


  
      char *decrypted_message = malloc(RSA_size(keypair));
      if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypted_message, (unsigned char*)decrypted_message,
                             keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(),err);
        fprintf(stderr,RED "Error decrypting message: %s\n" RESET, err);
      } else {
        printf(GREEN "Decrypted message: %s\n" RESET, decrypted_message);
      }
    }

  }
  
  return 0;
}




