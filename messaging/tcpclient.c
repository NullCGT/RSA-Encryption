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
#define KEYBITS 4096
#define BUFF_SIZE KEYBITS / 4
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

//Method declarations
void act_as_client (tosend_t* package);
void act_as_middle_server (tosend_t* package);
void act_as_server (tosend_t* package);
char *encryption(RSA* keypair_pub, char* message);
tosend_t* struct_encryption(node_t* relay_data, tosend_t* package, char* sender_ip, RSA* pub_for_final);
tosend_t* struct_decryption(RSA* keypair, tosend_t* package, int encrypt_len);
int create_socket();
void bind_me(int sockfd, char* ip);
struct sockaddr_in connect_to_server(int sockfd, char* ip);
int accept_connection(int sockfd, struct sockaddr_in cl_addr);
void* receiveMessage(void* socket);
void act_as_client(tosend_t* package);
void act_as_server(tosend_t* package);
void initialize_package(tosend_t* package, int num_middle_servers, char* final_ip, char* message);
char* serialize(tosend_t* package);
tosend_t* deserialize(char* serial);

//Initialization of our package struct for cleanup
//
void initialize_package(tosend_t* package, int num_of_middle_servers, char* final_ip, char* message) {
  package->index = 0;
  package->num_of_middle_servers = num_of_middle_servers;
  
  for(int i = 0; i < ARBITRARY_MAX_RELAYS; i++) 
    package->ip[i] = (char*)malloc(sizeof(char)*513); 

  package->message = (char*) malloc(sizeof(char)*1000);
  message = "Welcome to our chat!"; //DUMMY MESSAGE;
  strcpy(package->message, message);
}

//An RSA generator created on bad practice
RSA* do_bad_things(char* ip_address) {
  //srand(atoi(ip_address));
  srand(1);
  RSA* keypair = RSA_generate_key(KEYBITS, 3, NULL, NULL);
  return keypair;
}

//Enrypts our message using our RSA token
char *encryption(RSA* keypair_pub, char* message){
  printf("encrypting!\n");
  char *encrypted_message = malloc(RSA_size(keypair_pub));
  int encrypt_len;
  char *err = malloc(130);

  if((encrypt_len = RSA_public_encrypt(RSA_size(keypair_pub)-42, (unsigned char*) message,
                                       (unsigned char*)encrypted_message, keypair_pub, RSA_PKCS1_OAEP_PADDING)) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr,"Error encrypting message: %s\n", err);
  } else {
    // printf("%s\n" , message);
  }
  return encrypted_message;
}

//Handles the encription of our package. Encrypts the IP adddresses in multiple
//layers
tosend_t* struct_encryption(node_t* relay_data, tosend_t* package, char* final_ip, RSA* pub_for_final) {
  // For now this will all be using the same keypair, because we don't have a layout for multiple keys yet.
  int counter = 1;
  strcpy(package->ip[0], encryption(pub_for_final,final_ip));

  while (relay_data != NULL) {
    strcpy(package->ip[counter], relay_data->ip_address);
    counter++;
    for (int i = 0; i < counter; i++) {
      strcpy(package->ip[i], encryption(relay_data->keypair_pub, package->ip[i]));
   }
   relay_data = relay_data->next;
  }
  printf("After the ecription method is called\n");
  return package;
}

tosend_t* struct_decryption(RSA* keypair, tosend_t* package, int encrypt_len){
  char *decrypted_message = malloc(RSA_size(keypair));
  char *err = malloc(130);
  int middle= package->num_of_middle_servers;
  //check this next line if errors.
  for (int i = package->index; i <=middle; i++) {
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)package->ip[middle-i], (unsigned char*)package->ip[middle-i], keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
      ERR_load_crypto_strings();
      ERR_error_string(ERR_get_error(),err);
      fprintf(stderr,"Error decrypting message: %s\n", err);
    }
  }
  package->index++;
  return package;
}

//a mockup decrypt function for testing purposes
char* decrypt(char* encrypted_IP) {
  return encrypted_IP;
}

//A serializer for the package struct to a single string, separated by "field_delimeter" to
//send through sockets; separate the ip addresses stored in the array eith "ip_delimeter" string
char* serialize(tosend_t* package) {

  char* field_delimeter = "field_delimeter";
  char* ip_delimeter = "ip_delimeter";
  
  char* serial = (char*) malloc(sizeof(char)*BUFF_SIZE);
  char* temp = (char*) malloc(sizeof(char)*BUFF_SIZE);

  sprintf(temp, "%d", package->index);
  strcat(serial,temp);
  strcat(serial, field_delimeter);

  sprintf(temp, "%d", package->num_of_middle_servers);
  strcat(serial,temp);
  strcat(serial, field_delimeter);

  int i=0;
  while(package->ip[i] != NULL){
    strcat(serial,package->ip[i]);
    strcat(serial, ip_delimeter);
    i++;
  }
  
  strcat(serial,field_delimeter);
  strcat(serial, package->message);
  printf("%s\n",serial);
  return serial;
}


//Deserializes the inputted string.
//Splits each package section with the "field_delimeter" string,
//and splits ip addresses with the "ip_delimeter" string.
//@returns: tosend_t stuct
tosend_t* deserialize(char* serial){

  char* field_delimeter = "field_delimeter";
  char* ip_delimeter = "ip_delimeter";

  tosend_t* package = (tosend_t*) malloc(sizeof(tosend_t));
  
  char* saveptr1 = (char*) malloc(sizeof(char)*(512 + strlen(field_delimeter) + 1));
  char* saveptr2 = (char*) malloc(sizeof(char)*((512 + strlen(ip_delimeter) + 1)*(package->num_of_middle_servers + 1)));
  char* token = (char*) malloc(sizeof(char)*512);

  package->index = atoi(strtok_r (serial, field_delimeter, &saveptr1)); //seg
  package->num_of_middle_servers = atoi(strtok_r(NULL, field_delimeter, &saveptr1));

  char* ip_addresses = (char*) malloc(sizeof(char)*((512 + strlen(ip_delimeter) + 1)*(package->num_of_middle_servers + 1)));
  
  strcpy(token, strtok_r(NULL, field_delimeter, &saveptr1));
  strcpy(ip_addresses, strtok_r(token, field_delimeter, &saveptr2));

  strcpy(ip_addresses, strtok_r (token, ip_delimeter, &saveptr2));
  for(int i=0; i < package->num_of_middle_servers; i++){
    strcpy(package->ip[i], ip_addresses);
    strcpy(ip_addresses, strtok_r(NULL, ip_delimeter, &saveptr2));
  }

  strcpy(package->message, strtok_r(NULL, field_delimeter, &saveptr1));

  return package;
}



//Creates a socket
//@returns:
//  0 on success
//  1 on failure
int create_socket() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    printf("Error creating socket!\n");
    exit(1);
  }

  return sockfd;
}

//Binds the socket to the IP adddress and Port.
//@returns
//   void
void bind_me(int sockfd, char* ip) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;

  if (ip == NULL) addr.sin_addr.s_addr = INADDR_ANY;
  else  addr.sin_addr.s_addr = inet_addr(ip);
  addr.sin_port = PORT;

  int ret = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
  if (ret < 0) {
    printf("Error binding!\n");
    exit(1);
  }
  printf("Binding done...\n");
}

//Connects to a server given the socket to use and the ip address of the server.
//@returns
//   sockaddr_in struct which contains the connected socket
struct sockaddr_in connect_to_server(int sockfd, char* ip) {
  struct sockaddr_in addr;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);
  addr.sin_port = PORT;

  int ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
  if (ret == -1) {
    printf("Error connecting to the server!\n");
    exit(1);
  }

  return addr;
}

//
//Accepts the socket connection made by the connect_to_server method
//Called after the server gets the initial request from the client
int accept_connection(int sockfd, struct sockaddr_in cl_addr) {
  int size = sizeof(cl_addr);
  int newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &size); //take in a sockaddr
  if (newsockfd < 0) {
    printf("Error accepting connection!\n");
    exit(1);
  }

  return newsockfd;
}

//Takes in message from the socket. The messsage can only be a string
void* receiveMessage(void* socket) {
  int ret;
  tosend_t* package;
  char* serializedPackage; 

  package = (tosend_t*) malloc(sizeof(tosend_t));
  serializedPackage = (char*) malloc(sizeof(char)*BUFF_SIZE);

  for (;;) {
    ret = recvfrom((int) (intptr_t)socket, serializedPackage, sizeof(char*), 0, NULL, NULL);
    if (ret < 0) printf("Error receiving the message!\n");
    else {
      package = deserialize(serializedPackage);
 
      if (package->index >= package->num_of_middle_servers) {
        fputs(package->message, stdout);
        exit(0); //not sure about this i forget why it's here
      }
      else act_as_middle_server(package);
    }
  }
}

//Turns our program to act as a client. Prompts the use for a message and sends
//it forward
void act_as_client(tosend_t* package) {
  struct sockaddr_in addr, cl_addr;
  int sockfd, ret;
  char* buffer;
  char* serializedMessage;
  char* my_ip;
  pthread_t rThread;
  RSA* server_keypair;

  my_ip = "132.161.196.12";
  server_keypair = do_bad_things(my_ip);
  //struct_decryption(server_keypair, package, sizeof(server_keypair));
  
  sockfd = create_socket();
  addr = connect_to_server(sockfd, "132.161.196.124");

  printf("Enter your messages one by one and press return key!\n");
  //creating a new thread for receiving messages from the server
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  buffer = (char*) malloc(sizeof(char)*BUFF_SIZE);
  serializedMessage = (char*) malloc(sizeof(char)*BUFF_SIZE);
  
  while (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package->message, buffer);
    strcpy(serializedMessage, serialize(package));
    ret = sendto(sockfd, serializedMessage, sizeof(char)*BUFF_SIZE, 0, (struct sockaddr*) &addr, sizeof(addr));
    if (ret < 0) {
      printf("Error sending data!\n");
    }
  }
  
  close(sockfd);
  pthread_exit(NULL);

  return;
}

//Turns our program into a middle man. It waits for a connection to be made, waits
//to recieve a message, decrypts the message, and sends the package to the next
//node
void act_as_middle_server(tosend_t* package) {
  printf("Act_as Client has been called\n");
  struct sockaddr_in addr, cl_addr;
  int sockfd, ret;
  char* buffer;
  char* serializedMessage;
  char* serverAddr;
  char* my_ip; 
  pthread_t rThread;
  RSA* server_keypair;

  
  my_ip = "this is where the ip would go.";
  server_keypair = do_bad_things(my_ip);
  struct_decryption(server_keypair, package, sizeof(server_keypair));
  
  serverAddr = (char*) malloc(sizeof(char)*512);
  strcpy(serverAddr, package->ip[package->index]); 

  sockfd = create_socket();
  addr = connect_to_server(sockfd, serverAddr);

  printf("Enter your messages one by one and press return key!\n");

  //creating a new thread for receiving messages from the server
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  buffer = (char*) malloc(sizeof(char)*BUFF_SIZE);
  serializedMessage = (char*) malloc(sizeof(char)*BUFF_SIZE);
  
  if (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package->message, buffer);
    strcpy(serializedMessage, serialize(package));
    ret = sendto(sockfd, serializedMessage, sizeof(char)*BUFF_SIZE, 0, (struct sockaddr*) &addr, sizeof(addr));
    if (ret < 0) {
      printf("Error sending data!\n");
    }
  }

  close(sockfd);
  pthread_exit(NULL);
  act_as_server(package);
  
  return;
}


//Turns our program into the end server. It waits for a connection to be made, waits
//to recieve a message, decrypts the message, and displays the message to the
//user
void act_as_server(tosend_t* package) {

  struct sockaddr_in cl_addr;
  int sockfd, newsockfd, ret;
  char* buffer;
  char* serializedMessage;
  pid_t childpid;
  pthread_t rThread;

  sockfd = create_socket();

  bind_me(sockfd, NULL);

  printf("Waiting for a connection...\n");
  listen(sockfd, 5); //start the listening in the socket

  newsockfd = accept_connection(sockfd, cl_addr);
  printf("Enter your messages one by one and press return key!\n");

  //creating a new thread for receiving messages from the client
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)newsockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  buffer = (char*) malloc(sizeof(char)*BUFF_SIZE);
  serializedMessage = (char*) malloc(sizeof(char)*BUFF_SIZE);
  
  while (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package->message, buffer);
    strcpy(serializedMessage, serialize(package));
    ret = sendto(sockfd, serializedMessage, sizeof(char)*BUFF_SIZE, 0, (struct sockaddr*) &cl_addr, sizeof(cl_addr));
    if (ret < 0) {
      printf("Error sending data!\n");
    }
  }

  close(newsockfd);
  close(sockfd);
  pthread_exit(NULL);
 
 return;
}


//Reads a list of IP addresses from file
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


node_t* initialize_ip_keys() {

node_t* node = read_file();

/*
  while(node != NULL){
    printf("%s", node->ip_address);
    node = node->next;
  }
  while(node != NULL) {
    BIO *private = BIO_new(BIO_s_mem());
    BIO *public = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(private, node->keypair_pub, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(public, node->keypair_pub);
    size_t pri_len = BIO_pending(private);
    size_t pub_len = BIO_pending(public);

    char* pri_key = malloc(pri_len + 1);
    char* pub_key = malloc(pub_len + 1);

    BIO_read(private, pri_key, pri_len);
    BIO_read(public, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    printf("%s\n", pri_key);
    printf("%s\n", pub_key);
    node=node->next;
  }
  */
  return node;


}

//Main function. Switches between act_as_client, act_as_server, and act_as_middle_server
//depending on the arguments given
int main(int argc, char**argv) {

  OpenSSL_add_all_algorithms();

  node_t* relay_data; 
  tosend_t* package;
  package = (tosend_t*) malloc(sizeof(tosend_t));

  if (argc > 2) {
    relay_data = initialize_ip_keys();
    initialize_package(package, atoi(argv[1]), (char*) argv[2], (char*) argv[3]);
    struct_encryption(relay_data,package, (char*) argv[2], do_bad_things(argv[2]));
    act_as_client(package);
  } else {
    initialize_package(package, 2, "", "");
    act_as_server(package);
  }
  return 0;
}
