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

#include "socket_helper.h"
#include "encryption_helper.h"

//http://www.theinsanetechie.in/2014/01/a-simple-chat-program-in-c-tcp.html
//https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-opensll/

void act_as_client (tosend_t package);
void act_as_middle_server (tosend_t package);
void act_as_server (tosend_t package);
void initialize_package(tosend_t* package, int num_middle_servers, char* final_ip);
void* receiveMessage(void* socket);

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
  pthread_t rThread;
  RSA* server_keypair;
  char* serverAddr;

  server_keypair = do_bad_things(NULL);
  struct_decryption(server_keypair, package, sizeof(server_keypair));
  printf("%s\n",package.ip[package.index]);
  serverAddr = (char*) malloc(sizeof(char)*16);
  strcpy(serverAddr, package.ip[package.index]);

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

  while (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package.message, buffer);
    ret = sendto(sockfd, (tosend_t *)&package,(1024+ sizeof(package)), 0, (struct sockaddr*) &addr, sizeof(addr));
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
  struct sockaddr_in addr, cl_addr;
  int sockfd, ret;
  char* buffer;
  char* serverAddr;
  pthread_t rThread;
  RSA* server_keypair;

  server_keypair = do_bad_things(NULL);
  //struct_decryption(server_keypair, package, sizeof(server_keypair));

  serverAddr = (char*) malloc(sizeof(char)*16);
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

  //
  if (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package.message, buffer);
    ret = sendto(sockfd, (tosend_t*)&package, (1024+sizeof(package)), 0, (struct sockaddr*) &addr, sizeof(addr));
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
  ret = pthread_create(&rThread, NULL, receiveMessage, (void*)(intptr_t)sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }
  //we aren't getting the package back. so we aren't making sure the changes in
  //recieve message are saving

  buffer = (char*) malloc(sizeof(char)*BUFF_SIZE);

  while (fgets(buffer, BUFF_SIZE, stdin) != NULL) {
    strcpy(package.message, buffer);
    ret = sendto(sockfd, (tosend_t*)&package, (1024+sizeof(package)), 0, (struct sockaddr*) &cl_addr, sizeof(cl_addr));
    if (ret < 0) {
      printf("Error sending data!\n");
    }
  }

  close(newsockfd);
  close(sockfd);
  pthread_exit(NULL);

  return;
}


//Initialization of our package struct for cleanup
//@returns void
void initialize_package(tosend_t* package, int num_of_middle_servers, char* final_ip) {
  package->index = 0;
  package->num_of_middle_servers = num_of_middle_servers;
  strncpy(package->ip[num_of_middle_servers], final_ip, sizeof(char)*16);
}

//Takes in a string package from the socket. If given to the end server, it
//deserializes the package and prints the message to the user. Otherwise, runs
//act_as_middle_server.
//@returns
//   void
void* receiveMessage(void* socket) {
  int ret;
  tosend_t *package=malloc(sizeof(tosend_t));

  for (;;) {
    ret = recvfrom((int) (intptr_t)socket, package, sizeof(*package), 0, NULL, NULL); 
    else {
      if (package->index >= package->num_of_middle_servers) fputs(package->message, stdout);
      else act_as_middle_server(*package);
    }
  }
}

//Main function. Switches between act_as_client, act_as_server, and act_as_middle_server
//depending on the command line arguments
//server:  ./tcpclient
//client: ./tcpclient ip num_of_middle_servers
int main(int argc, char**argv) {

  OpenSSL_add_all_algorithms();

  node_t* relay_data;
  tosend_t* package = (tosend_t*) malloc(sizeof(tosend_t));

  if (argc > 2) {
    relay_data = read_file(); //initializes a linked list containing ip addresses and RSA keys
    initialize_package(package, atoi(argv[1]), (char*) argv[2]);
    struct_encryption(relay_data, *package, do_bad_things(argv[2]));
    act_as_client(*package);
  } else {
    initialize_package(package, 0 , "");
    act_as_server(*package);
  }
  return 0;
}
