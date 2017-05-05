#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
// This MUST be compiled using gcc -o Testencrypt Testencrypt.c -lssl -lcrypto

// This code is copied from https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-opensll/

#define KEYBITS 2048
#define PUBFILENAME "PUBKEY.pem"
#define PRIVFILENAME "PRIVKEY.pem"
// http://stackoverflow.com/questions/3585846/color-text-in-terminal-applications-in-unix
#define CYAN "\x1B[36m"
#define GREEN "\x1B[32m"
#define RED "\x1B[31m"
#define RESET "\x1B[0m"
#define NUM_SERVER

typedef struct ip_key_t  {
  char* ip_address;
  RSA* keypair_pub;
} ip_key;

typedef struct node_t {
  ip_key compdata;
  struct node_t* next;
} node;

typedef struct hashmap_element{
  int size;
  ip_key* data;
}hash;

typedef struct tosend_t {
  int index;
  char* ip[4];
  char message; 
} tosend;


bool in_hashmap(char*ip,hash hashmap_server){
  for(int i=0;i<NUM_SERVER;i++){
    if (strcmp(ip, hashmap_server.data[i].ip_address) == 0){
      return true;
    }
  }
    return false;
}

RSA* pub_in_list(char*ip,node ip_server){
  while(ip_server!=NULL){
    if (strcmp(ip, ip_server.compdata.ip_address) == 0){
      return ip_server.compdata.keypair_pub;
    }else{
      ip_server=ip_server->next;
    }
  }
  return;
}  
  
RSA * seperate_pub_key(RSA *keypair){
  BIO*public = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(public, keypair);
  RSA*keypair_pub = NULL;
  PEM_read_bio_RSAPublicKey(public, &keypair_pub, NULL,NULL);
  return keypair_pub;
}

char *encryption(RSA* keypair_pub, char* message){
  char *encrypted_message = malloc(RSA_size(keypair_pub));
  int encrypt_len;
  char *err = malloc(130);

  if((encrypt_len = RSA_public_encrypt(strlen(message)+1, (unsigned char*) message,
                                       (unsigned char*)encrypted_message, keypair_pub, RSA_PKCS1_OAEP_PADDING)) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr,RED "Error encrypting message: %s\n" RESET, err);
  } else {
    printf(CYAN "%s\n" RESET, message);
  }
  return encrypted_message;
}

char *decryption(RSA* keypair, char* encrypted_message,int encrypt_len){
  char *decrypted_message = malloc(RSA_size(keypair));
  char *err = malloc(130);
  if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypted_message, (unsigned char*)decrypted_message,
                         keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(),err);
    fprintf(stderr,RED "Error decrypting message: %s\n" RESET, err);
  } else {
    printf(GREEN "Decrypted message: %s\n" RESET, decrypted_message);
  }
  return decrypted_message;
}

int main (void)
{

  RSA *keypair;
  FILE *file;
  BIO *private;
  BIO *public;
  char* pri_key;
  char* pub_key;
  char*ip0;
  char*ip1;
  char*ip2;
  RSA* pub0=pub_in_list(ip0,ip_server);
  RSA* pub1=pub_in_list(ip1,ip_server);
  RSA* pub2=pub_in_list(ip2,ip_server);
  RSA* pub[3];
  pub[0]=pub0;
  pub[1]=pub1;
  pub[2]=pub2;
  char encrypted[1]='t';
  char *message;

  tosend package;
  package.int = 0;
  package.ip[0] = ip0;
  package.ip[1] = ip1;
  package.ip[2] = ip2;
  package.message = "I AM A MESSAGE LOL";
  
  encryption(pub[2], package.ip[2]);
  for (int i = 0; i < 1; i++) {
    encryption(pub[1], package.ip[2-i]); 
  }
  for (int i = 0; i < 2; i++) {
    encryption(pub[0], package.ip[2-i]); 
  }

  
  // intialized as original message
  for (int i=0;i<3;i++){
    strcat(message,encrypted);
    encrypted=encryption(pub[2-i], encrypted);
    }

  //Testing
  RSA *keypair_pub;

  OpenSSL_add_all_algorithms();
  system("clear");
  
    keypair = RSA_generate_key(KEYBITS, 3, NULL, NULL);
    private = BIO_new(BIO_s_mem());
    public = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(private, keypair, NULL, NULL, 0, NULL, NULL);


    
        // Creates a keypair that contains only the public key (for struct purposes)
    // http://stackoverflow.com/questions/22521324/separating-public-and-private-keys-from-rsa-keypair-variable
    PEM_write_bio_RSAPublicKey(public, keypair);
    keypair_pub = NULL;
    PEM_read_bio_RSAPublicKey(public, &keypair_pub, NULL,NULL);


    PEM_write_bio_RSAPublicKey(public, keypair);
    size_t pri_len = BIO_pending(private);
    size_t pub_len = BIO_pending(public);

    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);

    BIO_read(private, pri_key, pri_len);
    BIO_read(public, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    
    
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

      char *encrypted_message = malloc(RSA_size(keypair_pub));
      int encrypt_len;
      char *err = malloc(130);

      if((encrypt_len = RSA_public_encrypt(strlen(message)+1, (unsigned char*) message,
                                           (unsigned char*)encrypted_message, keypair_pub, RSA_PKCS1_OAEP_PADDING)) == -1) {
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




