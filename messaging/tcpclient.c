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

int main(int argc, char**argv) {  
 struct sockaddr_in address;  
 int sockfd, ret; 
 char buffer[BUF_SIZE]; 
 char * IP;
 pthread_t rThread;

 // fetching the IP adress 
 if (argc < 2) {
  printf("enter IP address of the receiving end\n");
  exit(1);  
 }
 IP = argv[1]; 

 //creating the socket
 sockfd = socket(AF_INET, SOCK_STREAM, 0);  
 if (sockfd < 0) {  
  printf("Error creating socket!\n");  
  exit(1);  
 }  
 
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

 // receiving messages from the other User
 ret = pthread_create(&rThread, NULL, receiveMessage, (void *) sockfd);
 if (ret) {
  printf("ERROR: Return Code from pthread_create() is %d\n", ret);
  exit(1);
 }

 //sending messages to another User
 while (fgets(buffer, BUF_SIZE, stdin) != NULL) {
  ret = sendto(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *) &address, sizeof(address));  
  if (ret < 0) {  
   printf("Error sending data!\n\t-%s", buffer);  
  }
 }

 close(sockfd);
 pthread_exit(NULL);
 
 return 0;    
} 
