#include"stdio.h"
#include"stdlib.h"
#include"sys/types.h"
#include"sys/socket.h"
#include"string.h"
#include"netinet/in.h"
#include"pthread.h"

#define PORT 4444
#define BUF_SIZE 2000
#define CLADDR_LEN 100

void * receiveMessage(void * socket) {
 int recieved;
 char buffer[BUF_SIZE]; 
 memset(buffer, 0, BUF_SIZE);
 
 for (;;) {
  recieved = recvfrom((int) socket, buffer, BUF_SIZE, 0, NULL, NULL);  
  if (recieved < 0) printf("Error receiving data!\n");    
  else fputs(buffer, stdout);
 }
}

void main() {
 struct sockaddr_in addr, cl_addr;
 int sockfd, len, ret, newsockfd;
 char buffer[BUF_SIZE];
 pid_t childpid;
 char clientAddr[CLADDR_LEN];
 pthread_t rThread;
 
 sockfd = socket(AF_INET, SOCK_STREAM, 0);
 if (sockfd < 0) {
  printf("Error creating socket!\n");
  exit(1);
 }
 printf("Socket created...\n");
 
 memset(&addr, 0, sizeof(addr));
 addr.sin_family = AF_INET;
 addr.sin_addr.s_addr = INADDR_ANY;
 addr.sin_port = PORT;
 
 ret = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
 if (ret < 0) {
  printf("Error binding!\n");
  exit(1);
 }
 printf("Binding done...\n");

 printf("Waiting for a connection...\n");
 listen(sockfd, 5); //start the listening in the socket


 len = sizeof(cl_addr);
 newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &len); //take in a sockaddr
 if (newsockfd < 0) {
  printf("Error accepting connection!\n");
  exit(1);
 } 

 inet_ntop(AF_INET, &(cl_addr.sin_addr), clientAddr, CLADDR_LEN); //converts the address recieved into an ipaddress
 printf("Connection accepted from %s...\n", clientAddr); 
 
 memset(buffer, 0, BUF_SIZE);
 printf("Enter your messages one by one and press return key!\n");

 //creating a new thread for receiving messages from the client
 ret = pthread_create(&rThread, NULL, receiveMessage, (void *) newsockfd);
 if (ret) {
  printf("ERROR: Return Code from pthread_create() is %d\n", ret);
  exit(1);
 }

 while (fgets(buffer, BUF_SIZE, stdin) != NULL) {
  ret = sendto(newsockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &cl_addr, len);  
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
