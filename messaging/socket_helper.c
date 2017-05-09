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

int accept_connection(int sockfd, struct sockaddr_in cl_addr) {
  int size = sizeof(cl_addr);
  int newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &size); //take in a sockaddr
  if (newsockfd < 0) {
    printf("Error accepting connection!\n");
    exit(1);
  }
  return newsockfd;
}

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

int create_socket() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    printf("Error creating socket!\n");
    exit(1);
  }

  return sockfd;
}

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
