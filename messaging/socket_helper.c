#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "structs.h"

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
