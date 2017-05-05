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
  // do the decryption here and store it somewhere;
  // if the decryption leads to a new IP address in act_as_server break out and act_as_client
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

void act_as_server () {
	struct sockaddr_in address, client_address;
  	int sockfd, len, ret, new_sockfd;
	char buffer[BUF_SIZE];
  	pid_t childpid;
 	char clien_IP[CLIENT_IP_LENGTH];
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
	  ret = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
	  if (ret < 0) {
	  	printf("Error binding!\n");
		exit(1);
	   }

	   // waiting for the connection
	   listen(sockfd, 5);

	   //connecting with the client
	   len = sizeof(client_address);
 	   new_sockfd = accept(sockfd, (struct sockaddr *) &clent_address, &len);
 	   if (new_sockfd < 0) {
 		 printf("Error accepting connection!\n");
  		 exit(1);
 	   }

	   //accepting connection from the client
	   inet_ntop(AF_INET, &(client_address.sin_addr), client_IP, CLIENT_IP_LEN);

		memset(buffer, 0, BUF_SIZE);

		//creating a new thread for receiving messages from the client
 		ret = pthread_create(&rThread, NULL, receiveMessage, (void *) new_sockfd);
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



int main(int argc, char**argv) {
  //all these should be moved to the act_as_server
  struct sockaddr_in client_address;
  int ret, len, new_sockfd;
  char client_IP[CLIENT_IP_LEN];
  pid_t child_pid;


 // fetching the IP adress
 // if no IP as an argument, should be running as a server
 if (argc < 2)  act_as_server();
 else {
   //client
   char* IP = argv[1];
   act_as_client(IP);
   }
 }

 return 0;
}
