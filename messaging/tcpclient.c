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

//Method declarations
void act_as_client (tosend_t package);
void act_as_middle_server (tosend_t package);
void act_as_server (tosend_t package);
int accept_connection(int sockfd, struct sockaddr_in cl_addr);
void bind_me(int sockfd, char* ip);
struct sockaddr_in connect_to_server(int sockfd, char* ip);
int create_socket();

RSA* do_bad_things(char* ip_address);
char *encryption(RSA* keypair_pub, char* message);
void initialize_package(tosend_t package, int num_middle_servers, char* final_ip);
void* receiveMessage(void* socket);
node_t* read_file();
tosend_t struct_encryption(node_t* relay_data, tosend_t package, RSA* pub_for_final);
tosend_t struct_decryption(RSA* keypair, tosend_t package, int encrypt_len);


//Accepts the socket connection made by the connect_to_server method. Called
//after the server gets the initial request from the client
//@returns
//    0 on success
//   -1 on failure
int accept_connection(int sockfd, struct sockaddr_in cl_addr) {
  int size = sizeof(cl_addr);
  int newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &size); //take in a sockaddr
  if (newsockfd < 0) {
    printf("Error accepting connection!\n");
    exit(1);
  }
  return newsockfd;
}

//The user runs as a client. Takes a package with the encripted ip adress, decrypts
//it's own layer, and connects to the next node using that ip address. Once the
//connection is established, it prompts the user for a message and then sends it
//to the connected node.
//@returns
//    void
void act_as_client(tosend_t package) {
  struct sockaddr_in addr, cl_addr;
  int sockfd, ret;
  char* buffer;
  char* my_ip;
  pthread_t rThread;
  RSA* server_keypair;

  server_keypair = do_bad_things(my_ip);
  //struct_decryption(server_keypair, package, sizeof(server_keypair));

  sockfd = create_socket();
  addr = connect_to_server(sockfd, "132.161.196.61");

  printf("Enter your messages one by one and press return key!\n");
  //creating a new thread for receiving messages from the server
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  buffer = (char*) malloc(sizeof(char)*BUFF_SIZE);

  while (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package.message, buffer);
    ret = sendto(sockfd, &package, sizeof(package), 0, (struct sockaddr*) &addr, sizeof(addr));
    if (ret < 0) {
      printf("Error sending data!\n");
    }
  }

  close(sockfd);
  pthread_exit(NULL);

  return;
}

//The user runs as a middle man server. It listens for a connection to be made,
//then awaits a message, decrypts the message, and sends the package to the next
//node.
//@returns
//    void
void act_as_middle_server(tosend_t package) {
  printf("Act_as Client has been called\n");
  struct sockaddr_in addr, cl_addr;
  int sockfd, ret;
  char* buffer;
  char* serverAddr;
  char* my_ip;
  pthread_t rThread;
  RSA* server_keypair;

  my_ip = "this is where the ip would go.";
  server_keypair = do_bad_things(my_ip);
  // struct_decryption(server_keypair, package, sizeof(server_keypair));

  serverAddr = (char*) malloc(sizeof(char)*20);
  printf("\n%d\n",sizeof(package.ip[package.index]));
  printf("Package index: %d\n", package.index);
  strcpy(serverAddr, package.ip[package.index]);

  //connects to the next node
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

  if (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package.message, buffer);
    ret = sendto(sockfd, &package, sizeof(package), 0, (struct sockaddr*) &addr, sizeof(addr));
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
//@returns
//   void
void act_as_server(tosend_t package) {

  struct sockaddr_in cl_addr;
  int sockfd, newsockfd, ret;
  char* buffer;
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

  while (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package.message, buffer);
    ret = sendto(sockfd, &package, sizeof(package), 0, (struct sockaddr*) &cl_addr, sizeof(cl_addr));
    if (ret < 0) {
      printf("Error sending data!\n");
    }
  }

  close(newsockfd);
  close(sockfd);
  pthread_exit(NULL);

  return;
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


//Initialization of our package struct for cleanup
//@returns void
void initialize_package(tosend_t package, int num_of_middle_servers, char* final_ip) {
  package.index = 0;
  package.num_of_middle_servers = num_of_middle_servers;
  strncpy(package.ip[num_of_middle_servers], final_ip, sizeof(char)*16);
}

//Takes in a string package from the socket. If given to the end server, it
//deserializes the package and prints the message to the user. Otherwise, runs
//act_as_middle_server.
//@returns
//   void
void* receiveMessage(void* socket) {
  int ret;
  tosend_t package;
  
  for (;;) {
    ret = recvfrom((int) (intptr_t)socket, &package, sizeof(package), 0, NULL, NULL);
    if (ret < 0) printf("Error receiving the message!\n");
    else {
      if (package.index >= package.num_of_middle_servers) fputs(package.message, stdout);
      else act_as_middle_server(package);
    }
  }
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


//Handles the encription of our package. Encrypts the IP adddresses in multiple
//layers
//@returns
//   tosend_t*
tosend_t struct_encryption(node_t* relay_data, tosend_t package, RSA* pub_for_final) {
  // For now this will all be using the same keypair, because we don't have a layout for multiple keys yet.
  int counter = 0;
  strncpy(package.ip[package.num_of_middle_servers],
          encryption(pub_for_final,package.ip[package.num_of_middle_servers]), BUFF_SIZE);

  while (relay_data != NULL) {
    strcpy(package.ip[counter], relay_data->ip_address);

    for (int i = 0; i <= counter; i++) {
      strcpy(package.ip[i], encryption(relay_data->keypair_pub, package.ip[i]));
    }
    relay_data = relay_data->next;
    counter++; 
  }
  return package;
}


//Handles the decryption of our package. Decrypts one entire layer of IP addresses.
//@returns
//   tosend_t*
tosend_t struct_decryption(RSA* keypair, tosend_t package, int encrypt_len){
  char *decrypted_message = malloc(RSA_size(keypair));
  char *err = malloc(130);
  
  for (int i = package.index; i <= package.num_of_middle_servers; i++) {
    if(RSA_private_decrypt(encrypt_len,
                            (unsigned char*)package.ip[i],
                            (unsigned char*)package.ip[i],
                            keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
      ERR_load_crypto_strings();
      ERR_error_string(ERR_get_error(),err);
      fprintf(stderr,"Error decrypting message: %s\n", err);
    }
  }
  
  package.index++;
  return package;
}


//Main function. Switches between act_as_client, act_as_server, and act_as_middle_server
//depending on the command line arguments
//server:  ./tcpclient
//client: ./tcpclient ip num_of_middle_servers
int main(int argc, char**argv) {

  OpenSSL_add_all_algorithms();

  node_t* relay_data;
  tosend_t package;

  if (argc > 2) {
    relay_data = read_file(); //initializes a linked list containing ip addresses and RSA keys
    initialize_package(package, atoi(argv[1]), (char*) argv[2]);
    //struct_encryption(relay_data,package, do_bad_things(argv[2]));
    act_as_client(package);
  } else {
    initialize_package(package, 0 , "");
    act_as_server(package);
  }
  return 0;
}
