#include <netdb.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <stdbool.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

//http://www.theinsanetechie.in/2014/01/a-simple-chat-program-in-c-tcp.html
//https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-opensll/

#define PORT 4444
#define BUF_SIZE 512
#define KEYBITS 4096
#define ARBITRARY_MAX_RELAYS 100

// Package that is sent from computer to computer.
typedef struct tosend {
  int index;
  int num_of_middle_servers;
  char* ip[ARBITRARY_MAX_RELAYS];
  char* message;
} tosend_t;

// Linked list implementation linking to an ip_address and RSA key
typedef struct node {
  char* ip_address;
  RSA* keypair_pub;
  struct node* next;
} node_t;

void act_as_client (tosend_t* package);
void act_as_server (tosend_t* package);
char *encryption(RSA* keypair_pub, char* message);
tosend_t* struct_encryption(node_t* relay_data, tosend_t* package, char* sender_ip);
bool struct_decryption(RSA* keypair, tosend_t* package, int encrypt_len);
int create_socket();
void bind_me(struct sockaddr_in addr, int sockfd);
void connect_to_server(struct sockaddr_in addr, int sockfd);
int accept_connection(int sockfd, struct sockaddr_in cl_addr);
void* receiveMessage(void* socket);
void act_as_client(tosend_t* package);
void act_as_server(tosend_t* package);
void initialize_package(tosend_t* package, int num_middle_servers, char* final_ip, char* message);

void encrypt(char* final_IP, char** ips, int len) {
  for (int i = 0; i < len; i++) {
    ips[i] = final_IP; 
  }
}

void initialize_package(tosend_t* package, int num_of_middle_servers, char* final_ip, char* message) {
  package->index = 0;
  package->num_of_middle_servers = num_of_middle_servers;
  package->message = message;

  char* ips[100];
  encrypt(final_ip, ips, 100);

  for (int i = 0; i < num_of_middle_servers; i++) {
    package->ip[i] = ips[i];
  }
}


RSA* do_bad_things(char* ip_address) {
  srand((unsigned int) ip_address);
  RSA* keypair = RSA_generate_key(KEYBITS, 3, NULL, NULL);
  return keypair;
}

char *encryption(RSA* keypair_pub, char* message){
  char *encrypted_message = malloc(RSA_size(keypair_pub));
  int encrypt_len;
  char *err = malloc(130);

  if((encrypt_len = RSA_public_encrypt(strlen(message)+1, (unsigned char*) message,
                                       (unsigned char*)encrypted_message, keypair_pub, RSA_PKCS1_OAEP_PADDING)) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr,"Error encrypting message: %s\n", err);
  } else {
    printf("%s\n", message);
  }
  return encrypted_message;
}

tosend_t* struct_encryption(node_t* relay_data, tosend_t* package, char* final_ip) {
  // For now this will all be using the same keypair, because we don't have a layout for multiple keys yet.
  int counter = 1;
  package->ip[0] = final_ip;
  while (relay_data != NULL) {
    package->ip[counter] = relay_data->ip_address;
    counter++;
    for (int i = 0; i < counter; i++) {
      package->ip[i] = encryption(relay_data->keypair_pub, package->ip[i]);
    }
    relay_data = relay_data->next;
  }
  return package;
}

bool struct_decryption(RSA* keypair, tosend_t* package, int encrypt_len){
  char *decrypted_message = malloc(RSA_size(keypair));
  char *err = malloc(130);
  //check this next line if errors.
  for (int i = package->index; i < package->num_of_middle_servers; i++) {
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)package->ip[i], (unsigned char*)package->ip[i],
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
      ERR_load_crypto_strings();
      ERR_error_string(ERR_get_error(),err);
      fprintf(stderr,"Error decrypting message: %s\n", err);
    } else {
      printf("Decrypted message: %s\n", decrypted_message);
    }
  }
  return (package->index == package->num_of_middle_servers);
}


char* decrypt(char* encrypted_IP) {
  return encrypted_IP; 
}

int create_socket() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);  
  if (sockfd < 0) {  
    printf("Error creating socket!\n");  
    exit(1);  
  }  
  printf("Socket created...\n");

  return sockfd; 
}

void bind_me(struct sockaddr_in addr, int sockfd) {
  int ret = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
  if (ret < 0) {
    printf("Error binding!\n");
    exit(1);
  }
  printf("Binding done...\n");
}

void connect_to_server(struct sockaddr_in addr, int sockfd) {
  int ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));  
  if (ret < 0) {  
    printf("Error connecting to the server!\n");  
    exit(1);  
  }  
  printf("Connected to the server...\n");  
}

int accept_connection(int sockfd, struct sockaddr_in cl_addr) {
  int size = sizeof(cl_addr); 
  int newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &size); //take in a sockaddr
  if (newsockfd < 0) {
    printf("Error accepting connection!\n");
    exit(1);
  }

  return newsockfd;
}

void* receiveMessage(void* socket) {
  int ret;
  tosend_t* package;

  package = (tosend_t*) malloc(sizeof(tosend_t));
    
  ret = recvfrom((int) (intptr_t)socket, package, sizeof(tosend_t), 0, NULL, NULL);
  if (ret < 0) printf("Error receiving the message!\n");
  else {
    if (package->index >= package->num_of_middle_servers) fputs(package->message, stdout);
    else act_as_server(package);
  }
}

void act_as_client(tosend_t* package) {
  printf("Act_as Client has been called\n");
  struct sockaddr_in addr, cl_addr;  
  int sockfd, ret;  
  char buffer[BUF_SIZE]; 
  pthread_t rThread;
  char* serverAddr;

  serverAddr = decrypt(package->ip[package->index]);

  // serverAddr = struct_decrypt (???????????) //THIS NEEDS WORK
  
  sockfd = create_socket(); 

  memset(&addr, 0, sizeof(addr));  
  addr.sin_family = AF_INET;  
  addr.sin_addr.s_addr = inet_addr(serverAddr);
  addr.sin_port = PORT;     

  connect_to_server(addr, sockfd); 

  memset(buffer, 0, BUF_SIZE);
  printf("Enter your messages one by one and press return key!\n");

  //creating a new thread for receiving messages from the server
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  package->index++; 

  //middle man should enter this once and go back to being a server 
  while (fgets(buffer, BUF_SIZE, stdin) != NULL) {
    strcpy(package->message, buffer);  
    ret = sendto(sockfd, package, sizeof(tosend_t), 0, (struct sockaddr *) &addr, sizeof(addr));  
    if (ret < 0) {  
      printf("Error sending data!\n\t-%s", buffer);  
    }
  }

  close(sockfd);
  pthread_exit(NULL);
 
  return;    
}  


void act_as_server(tosend_t* package) {
  printf("Act_as_server has been called\n");
  struct sockaddr_in addr, cl_addr;
  int sockfd, newsockfd, ret;
  char buffer[BUF_SIZE];
  pid_t childpid;
  pthread_t rThread;

  sockfd = create_socket(); 
 
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = PORT;
 
  bind_me(addr, sockfd); 

  printf("Waiting for a connection...\n");
  listen(sockfd, 5); //start the listening in the socket

  newsockfd = accept_connection(sockfd, cl_addr);

  memset(buffer, 0, BUF_SIZE);
  printf("Enter your messages one by one and press return key!\n");

  //creating a new thread for receiving messages from the client
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)newsockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  if (fgets(buffer, BUF_SIZE, stdin) != NULL) {
    strcpy(package->message, buffer); 
    ret = sendto(newsockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &cl_addr, sizeof(cl_addr));  
    if (ret < 0) {  
      printf("Error sending data!\n");  
      exit(1);
    }
 }   
 
 close(newsockfd);
 close(sockfd);

 pthread_exit(NULL);
 return;
}

/**
node_t* read_file(){
  FILE *ptr_file;
  char buf[1000];
  node_t* prev = NULL;
  ptr_file =fopen("ip.txt", "r");

  if (!ptr_file)
    return NULL;

  while (fgets(buf,1000, ptr_file)!=NULL){
    node_t * cur = (node_t*) malloc(sizeof(node_t));
    cur->ip_address = buf;
    cur->next = prev;
    prev = cur;
  } 

  fclose(ptr_file);

  return prev;
}
*/


int main(int argc, char**argv) {

  /*
  node_t* node = read_file();
  
  while(node != NULL){
    printf("%s", node->ip_address);
    node = node->next;
  }
 
  OpenSSL_add_all_algorithms();

  node_t* relay_data;
  */
  tosend_t* package;
  package = (tosend_t*) malloc(sizeof(tosend_t));
  
  if (argc > 2) {
    //initialize_package(package, (int) argv[1], (char*) argv[2], (char*) argv[3]);
    act_as_client(package); 
  } else {
    initialize_package(package, 2, "", "");
    act_as_server(package);
  }
  return 0;
}


