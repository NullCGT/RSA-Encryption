#include <openssl/err.h>
#include <openssl/rsa.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "structs.h"

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
  } /* else {
     printf("%s\n" , message);
  }
  // for debugging
    */
  return encrypted_message;
}


tosend_t* struct_encryption(node_t* relay_data, tosend_t *package, RSA* pub_for_final) {
  clock_t begin = clock();
  int counter = package->num_of_middle_servers;
  RSA* pub[package->num_of_middle_servers];
  for(int i = counter; i > 0;i--){
  for (int j = counter-1; j>=0; j--) {
      strcpy(package->ip[i], encryption(do_bad_things(package->ip[j]), package->ip[i]));
    }
  }
  clock_t end = clock();
  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("encryption time: %f\n", time_spent);
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

//Reads a list of IP addresses from file
//@returns
//   node_t*
node_t* read_file(){
  FILE *ptr_file;
  char buf[20];
  char* list[ARBITRARY_MAX_RELAYS];
  node_t* prev;

  ptr_file =fopen("ip.txt", "r");
  prev = NULL;
  if (!ptr_file) return NULL;

  //reading file
  while (fgets(buf,20, ptr_file)!=NULL){
    node_t* cur=(node_t*)malloc(sizeof(node_t));
    cur->ip_address=malloc(sizeof(char)*20);
    strcpy(cur->ip_address,buf);
    cur->keypair_pub = do_bad_things(cur->ip_address);
    cur->next = prev;
    prev=cur;
  }
  fclose(ptr_file);
  return prev;
}
