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

//http://www.theinsanetechie.in/2014/01/a-simple-chat-program-in-c-tcp.html

#define PORT 4444
#define BUF_SIZE 2000
#define CLIENT_IP_LENGTH 100

typedef struct tosend {
  int index;
  int num_of_middle_servers;
  char* ip[100];
  char* message;
} tosend_t;

void act_as_client (tosend_t*  package);

void encrypt(char* final_IP, char** ips, int len) {
  for (int i = 0; i < len; i++) {
    ips[i] = final_IP; 
  }
}

char* decrypt(char* encrypted_IP) {
  return encrypted_IP; 
}

void* receiveMessage(void * socket) {
  int ret;
  tosend_t* package = (tosend_t*) malloc(sizeof(tosend_t));
    
  ret = recvfrom((int) socket, package, sizeof(tosend_t), 0, NULL, NULL);
  if (ret < 0) printf("Error receiving the message!\n");
  else {
    if (package->index >= package->num_of_middle_servers) fputs(package->message, stdout);
    else act_as_client(package);
  }
}

void act_as_client (tosend_t*  package) {
  
  //creating the socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    printf("Error creating socket!\n");
    exit(1);
  }
  
  struct sockaddr_in address;
  char buffer[BUF_SIZE];
  pthread_t rThread;
  int ret;
  

  char* IP = decrypt(package->ip[package->index]); 
  //creating the package to send
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = inet_addr(IP);
  address.sin_port = PORT;

  //connecting to the server
  ret = connect(sockfd, (struct sockaddr *) &address, sizeof(address));
  if (ret < 0) {
    printf("Error connecting to the server!\n");
    exit(1);
  }

  memset(buffer, 0, BUF_SIZE);

  // receiving messages from the server
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  package->index++; 
  //sending messages to the server
  //while for continuous chat
  printf("Send your secret message!\n");
  if (fgets(buffer, BUF_SIZE, stdin) != NULL) {
    package->message = buffer; 
    ret = sendto(sockfd, package, sizeof(tosend_t), 0, (struct sockaddr *) &address, sizeof(address));
    if (ret < 0) printf("Error sending the message!\n\t-%s", buffer);
  }

  close(sockfd);
  pthread_exit(NULL);

}



void act_as_server () {
  
  struct sockaddr_in address, client_address;
  int sockfd, len, ret, new_sockfd;
  char buffer[BUF_SIZE];
  pid_t childpid;
  char client_IP[CLIENT_IP_LENGTH];
  pthread_t rThread;

  //creating the socket
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    printf("Error creating socket!\n");
    exit(1);
  }

  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr =INADDR_ANY;
  address.sin_port = PORT;

  //binding
  ret = bind(sockfd, (struct sockaddr *) &address, sizeof(address));
  if (ret < 0) {
    printf("Error binding!\n");
    exit(1);
  }

  // waiting for the connection
  listen(sockfd, 5);

  //connecting with the client
  len = sizeof(client_address);
  new_sockfd = accept(sockfd, (struct sockaddr *) &client_address, &len);
  if (new_sockfd < 0) {
    printf("Error accepting connection!\n");
    exit(1);
  }

  //accepting connection from the client
  inet_ntop(AF_INET, &(client_address.sin_addr), client_IP, CLIENT_IP_LENGTH);

  memset(buffer, 0, BUF_SIZE);

  //creating a new thread for receiving messages from the client
  ret = pthread_create(&rThread, NULL, receiveMessage, (void *) new_sockfd);
  if (ret) {
    printf("ERROR: Return Code from pthread_create() is %d\n", ret);
    exit(1);
  }

  if (fgets(buffer, BUF_SIZE, stdin) != NULL) {
    ret = sendto(new_sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &client_address, len);
    if (ret < 0) {
      printf("Error sending data!\n");
      exit(1);
    }
  }

  close(new_sockfd);
  close(sockfd);
  pthread_exit(NULL);
  return;
}



int main(int argc, char**argv) {

  if (argv[2] != NULL) {
    char* final_ip = argv[1];
    int num_of_middle_servers = (int)argv[2];
    
    char* ips[num_of_middle_servers];
    tosend_t* package = (tosend_t*) malloc(sizeof(tosend_t));

    package->index = 0;
    package->num_of_middle_servers = num_of_middle_servers;
    encrypt(final_ip, ips, 100);

    for (int i = 0; i < num_of_middle_servers; i++) {
      package->ip[i] = ips[i];
    }
    
    act_as_client(package); 
  } else act_as_server();

 return 0;
}
