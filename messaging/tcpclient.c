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
#define BUF_SIZE KEYBITS / 4
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
/*
void encrypt(char* final_IP, char** ips, int len) {
  for (int i = 0; i < len; i++) {
    strcpy(ips[i], final_IP);
  }
}
*/

//Initialization of our package struct for cleanup
void initialize_package(tosend_t* package, int num_of_middle_servers, char* final_ip, char* message) {
  package->index = 0;
  package->num_of_middle_servers = num_of_middle_servers;
  
  for(int i = 0; i < ARBITRARY_MAX_RELAYS; i++) 
    package->ip[i] = (char*)malloc(sizeof(char)*513); 

  package->message = (char*) malloc(sizeof(char)*1000);
  message = "Welcome to our chat!" //DUMMY MESSAGE;
  strcpy(package->message, message);
}

//An RSA generator created on bad practice
RSA* do_bad_things(char* ip_address) {
  srand(atoi(ip_address));
  RSA* keypair = RSA_generate_key(KEYBITS, 3, NULL, NULL);
  return keypair;
}

//Enrypts our message using our RSA token
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
    printf("%s\n" , message);
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
  return package;
}


tosend_t* struct_decryption(RSA* keypair, tosend_t* package, int encrypt_len){
  char *decrypted_message = malloc(RSA_size(keypair));
  char *err = malloc(130);
  int middle= package->num_of_middle_servers;
  //check this next line if errors.
  for (int i = package->index; i <=middle; i++) {
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)package->ip[middle-i], (unsigned char*)package->ip[middle-i],
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
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

//Creates a socket. Sockfd= 0 if successfull, -1 on failure.
int create_socket() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    printf("Error creating socket!\n");
    exit(1);
  }
  printf("Socket created...\n");

  return sockfd;
}

//Binds the socket to the IP adddress and Port
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

//Establishes connections to an awaiting server
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
  printf("Connected to the server...\n");

  return addr;
}

//Accepts the socket connection made by the connect_to_server method
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

  printf("cao");
  package = (tosend_t*) malloc(sizeof(tosend_t));
  printf("cao2");

  for (;;) {
    ret = recvfrom((int) (intptr_t)socket, package, sizeof(tosend_t), 0, NULL, NULL);
    if (ret < 0) printf("Error receiving the message!\n");
    else {
      if (package->index >= package->num_of_middle_servers) {
        fputs(package->message, stdout);
        exit(0);
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
  char buffer[BUF_SIZE];
  pthread_t rThread;
  char* serverAddr = "132.161.196.111";
 printf("2");
  //serverAddr = decrypt(package->ip[package->index]);
 printf("3");
  // serverAddr = struct_decrypt (???????????) //THIS NEEDS WORK

  sockfd = create_socket();
 printf("4");
  addr = connect_to_server(sockfd, serverAddr);
 printf("5");
  memset(buffer, 0, BUF_SIZE);
 printf("6");
  //creating a new thread for receiving messages from the server
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }
 printf("7");

  package->index++;
 printf("8");
  while (fgets(buffer, BUF_SIZE, stdin) != NULL) {

    //strcpy(package->message, buffer);
     ret = sendto(sockfd, package, sizeof(tosend_t), 0, (struct sockaddr *) &addr, sizeof(addr));
     if (ret < 0) {
        printf("Error sending data!\n\t-%s", buffer);
     }
  }
 printf("9");
  close(sockfd);
  pthread_exit(NULL);

  act_as_client(package);

  return;
}

//Turns our program into a middle man. It waits for a connection to be made, waits
//to recieve a message, decrypts the message, and sends the package to the next
//node
void act_as_middle_server(tosend_t* package) {
  printf("Act_as Client has been called\n");
  struct sockaddr_in addr, cl_addr;
  int sockfd, ret;
  char buffer[BUF_SIZE];
  pthread_t rThread;
  char* serverAddr;

  serverAddr = decrypt(package->ip[package->index]);

  // serverAddr = struct_decrypt (???????????) //THIS NEEDS WORK

  sockfd = create_socket();

  addr = connect_to_server(sockfd, serverAddr);

  memset(buffer, 0, BUF_SIZE);
  printf("Enter your messages one by one and press return key!\n");

  //creating a new thread for receiving messages from the server
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  package->index++;

  if (fgets(buffer, BUF_SIZE, stdin) != NULL) {
    strcpy(package->message, buffer);
    ret = sendto(sockfd, package, sizeof(tosend_t), 0, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
      printf("Error sending data!\n\t-%s", buffer);
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
  printf("Act_as_server has been called\n");
  struct sockaddr_in cl_addr;
  int sockfd, newsockfd, ret;
  char buffer[BUF_SIZE];
  pid_t childpid;
  pthread_t rThread;

  sockfd = create_socket();

  bind_me(sockfd, NULL);

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

 while (fgets(buffer, BUF_SIZE, stdin) != NULL) {
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


//Reads a list of IP addresses from file
node_t* read_file(){
  FILE *ptr_file;
  char buf[20];
  char* list[ARBITRARY_MAX_RELAYS];
  ptr_file =fopen("ip.txt", "r");
  node_t* prev = NULL;
  if (!ptr_file)
    return NULL;
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


//Main function. Switches between act_as_client, act_as_server, and act_as_middle_server
//depending on the arguments given
int main(int argc, char**argv) {
  
  node_t* node = read_file();

  while(node != NULL){
    printf("%s", node->ip_address);
    node = node->next;
  }
  /*
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
  OpenSSL_add_all_algorithms();

  node_t* relay_data;
  tosend_t* package;
  package = (tosend_t*) malloc(sizeof(tosend_t));

  if (argc > 2) {
    initialize_package(package, atoi(argv[1]), (char*) argv[2], (char*) argv[3]);
    //struct_encryption(relay_data, package, final_ip); <--- Need to figure out the sending of the final IP, and comment out some stuff in initialize_package
    printf("1");
    struct_encryption(relay_data,package, (char*) argv[2], do_bad_things(argv[2]));
    act_as_client(package);
  } else {
    initialize_package(package, 2, "", "");
    act_as_server(package);
  }
  return 0;
}
