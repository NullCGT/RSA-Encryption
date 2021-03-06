#include <openssl/rsa.h>

#pragma once

#define PORT 4444
#define KEYBITS 2048
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
  RSA* keypair_pub;
  struct node* next;
} node_t;
