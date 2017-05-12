#include <openssl/err.h>
#include <openssl/rsa.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "structs.h"

#pragma once

#define PORT 4444
#define KEYBITS 4096
#define BUFF_SIZE KEYBITS / 8
#define ARBITRARY_MAX_RELAYS 100
#define MSG_SIZE 1000

// Package that is sent from computer to computer.
typedef struct tosend {
  int index;
  int num_of_middle_servers;
  char ip[ARBITRARY_MAX_RELAYS][BUFF_SIZE];
  char message[MSG_SIZE];
} tosend_t;

// Linked list implementation linking to an ip_address and RSA key
typedef struct node {
  char* ip_address;
  struct node* next;
} node_t;

//An RSA generator created on bad practice
RSA* do_bad_things(char* ip_address) {
  //srand(atoi(ip_address));
  srand(1);
  RSA* keypair = RSA_generate_key(KEYBITS, 3, NULL, NULL);
  return keypair;
}

//Enrypts our message using our RSA token
//@returns
//   char*
char *encryption(RSA* keypair_pub, char* message){
  char *encrypted_message = malloc(RSA_size(keypair_pub));
  int encrypt_len;
  char *err = malloc(130);

  if((encrypt_len = RSA_public_encrypt(RSA_size(keypair_pub) - 42,
                                       (unsigned char*) message,
                                       (unsigned char*)encrypted_message,
                                       keypair_pub, RSA_PKCS1_OAEP_PADDING)) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr,"Error encrypting message: %s\n", err);
  } 
  return encrypted_message;
}


tosend_t* struct_encryption(node_t* relay_data, tosend_t *package, RSA* pub_for_final) {

  for(int i =package-> num_of_middle_servers; i > 0;i--){
  for (int j =package-> num_of_middle_servers; j>=0; j--) {
    strcpy(package->ip[i], encryption(do_bad_thing(package->ip[j]), package->ip[i]));
    }
  }
  return package;
}

tosend_t* struct_decryption(RSA* keypair, tosend_t *package, int encrypt_len){
  char *decrypted_message = malloc(RSA_size(keypair));
  char *err = malloc(130);
    
  package->index++;
  for (int i = package->index; i <=package->num_of_middle_servers; i++) {
    if(RSA_private_decrypt(encrypt_len,
                            (unsigned char*)package->ip[i],
                            (unsigned char*)package->ip[i],
                            keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
      ERR_load_crypto_strings();
      ERR_error_string(ERR_get_error(),err);
      fprintf(stderr,"Error decrypting message: %s\n", err);
    }
  }
  return package;
}
int main(){


}
