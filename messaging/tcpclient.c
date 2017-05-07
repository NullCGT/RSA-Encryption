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

typedef struct tosend {
  int index;
  int num_of_middle_servers;
  char* ip[100];
  char* message;
} tosend_t;

void act_as_client (tosend_t* package);

void encrypt(char* final_IP, char** ips, int len) {
  for (int i = 0; i < len; i++) {
    ips[i] = final_IP; 
  }
}

char* decrypt(char* encrypted_IP) {
  return encrypted_IP; 
}

int create_socket() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);  
  if (sockfd < 0) {  
    printf("Error creating socket!\n");  
    exit(1);  
  }  
  printf("Socket created...\n");

  return sockfd; 
}

void bind_me(struct sockaddr_in addr, int sockfd) {
  int ret = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
  if (ret < 0) {
    printf("Error binding!\n");
    exit(1);
  }
  printf("Binding done...\n");
}

void connect_to_server(struct sockaddr_in addr, int sockfd) {
 int ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));  
 if (ret < 0) {  
  printf("Error connecting to the server!\n");  
  exit(1);  
 }  
 printf("Connected to the server...\n");  
}

int accept_connection(int sockfd, struct sockaddr_in cl_addr) {
  int size = sizeof(cl_addr); 
  int newsockfd = accept(sockfd, (struct sockaddr *) &cl_addr, &size); //take in a sockaddr
  if (newsockfd < 0) {
    printf("Error accepting connection!\n");
    exit(1);
  }

  return newsockfd;
}

void* receiveMessage(void* socket) {
  int ret;
  tosend_t* package;

  package = (tosend_t*) malloc(sizeof(tosend_t));
    
  ret = recvfrom((int) (intptr_t)socket, package, sizeof(tosend_t), 0, NULL, NULL);
  if (ret < 0) printf("Error receiving the message!\n");
  else {
    if (package->index >= package->num_of_middle_servers) fputs(package->message, stdout);
    else act_as_client(package);
  }
}

void act_as_client(tosend_t* package) {  
 struct sockaddr_in addr, cl_addr;  
 int sockfd, ret;  
 char buffer[BUF_SIZE]; 
 pthread_t rThread;
 char* serverAddr;

 serverAddr = decrypt(package->ip[package->index]);
 
 sockfd = create_socket(); 

 memset(&addr, 0, sizeof(addr));  
 addr.sin_family = AF_INET;  
 addr.sin_addr.s_addr = inet_addr(serverAddr);
 addr.sin_port = PORT;     

 connect_to_server(addr, sockfd); 

 memset(buffer, 0, BUF_SIZE);
 printf("Enter your messages one by one and press return key!\n");

 //creating a new thread for receiving messages from the server
 ret = pthread_create(&rThread, NULL, receiveMessage, (void *) (intptr_t)sockfd);
 if (ret) {
  printf("ERROR: Return Code from pthread_create() is %d\n", ret);
  exit(1);
 }

 package->index++; 

 //middle man should enter this once and go back to being a server 
 while (fgets(buffer, BUF_SIZE, stdin) != NULL) {
   strcpy(package->message, buffer);  
   ret = sendto(sockfd, package, sizeof(tosend_t), 0, (struct sockaddr *) &addr, sizeof(addr));  
   if (ret < 0) {  
     printf("Error sending data!\n\t-%s", buffer);  
   }
 }

 close(sockfd);
 pthread_exit(NULL);
 
 return;    
}  


void act_as_server(tosend_t* package) {

 struct sockaddr_in addr, cl_addr;
 int sockfd, newsockfd, ret;
 char buffer[BUF_SIZE];
 pid_t childpid;
 pthread_t rThread;

 sockfd = create_socket(); 
 
 memset(&addr, 0, sizeof(addr));
 addr.sin_family = AF_INET;
 addr.sin_addr.s_addr = INADDR_ANY;
 addr.sin_port = PORT;
 
 bind_me(addr, sockfd); 

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

int main(int argc, char**argv) {
  tosend_t* package;
  
  package = (tosend_t*) malloc(sizeof(tosend_t));

  package->index = 0;
  if (argc > 3) {
    int num_of_middle_servers;
    char* final_ip;
    char* ips[num_of_middle_servers];
    
    strcpy(final_ip, argv[1]);
    num_of_middle_servers = atoi(argv[2]);
    package->num_of_middle_servers = num_of_middle_servers;
    
    encrypt(final_ip, ips, 100);

    for (int i = 0; i < num_of_middle_servers; i++) {
      package->ip[i] = ips[i];
    }
    
    act_as_client(package); 
  } else act_as_server(package);

 return 0;
}


