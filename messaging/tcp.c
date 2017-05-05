#include"stdio.h"
#include"stdlib.h"
#include"sys/types.h"
#include"sys/socket.h"
#include"string.h"
#include"netinet/in.h"
#include"netdb.h"
#include"pthread.h"

//http://www.theinsanetechie.in/2014/01/a-simple-chat-program-in-c-tcp.html

#define PORT 4444
#define BUF_SIZE 2000
#define CLIENT_IP_LEN 100

void * receiveMessage(void * socket) {
 int ret;
 char buffer[BUF_SIZE];
 memset(buffer, 0, BUF_SIZE);

 for (;;) {
  ret = recvfrom((int) socket, buffer, BUF_SIZE, 0, NULL, NULL);
  if (ret < 0) printf("Error receiving data!\n");
  else fputs(buffer, stdout);
 }
}

void act_as_client (char* IP) {

  //creating the socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    printf("Error creating socket!\n");
    exit(1);
  }
  struct sockaddr_in address,
  char buffer[BUF_SIZE];
  pthread_t rThread;
  int ret;

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

  //sending messages to the server
  while (fgets(buffer, BUF_SIZE, stdin) != NULL) {
    ret = sendto(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &address, sizeof(address));
    if (ret < 0) printf("Error sending data!\n\t-%s", buffer);
  }

  close(sockfd);
  pthread_exit(NULL);

}

int main(int argc, char**argv) {
  //all these should be moved to the act_as_server
  struct sockaddr_in client_address;
  int ret, len, new_sockfd;
  char client_IP[CLIENT_IP_LEN];
  pid_t child_pid;


 // fetching the IP adress
 // if no IP as an argument, should be running as a server
 if (argc < 2) {
   //server YAZAAAN put the server code here
   // in the server code once it reads the message do smth like decryptr(message) and that will return a true or false and if true add act_as_client (message)
   act_as_server()
 } else {
   //client
   char* IP = argv[1];
   act_as_client(IP);
   }
 }

 return 0;
}