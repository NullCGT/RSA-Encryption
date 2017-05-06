#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define sender_port_number 57777
#define reciever_port_number 57776


void error(char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{

  int socket_file_descriptor, accept_file_descriptor;

  char buffer[256];
  struct sockaddr_in server_address, client_address;
  int num_chars;
  int n;
  struct hostent *server;

 pid_t child_id = fork();
 if(child_id == -1) {
   return 1;
 } else if(child_id == 0) {
   //printf("in child thread\n");

   char buffer[256];
   if (argc < 2) {
      fprintf(stderr,"usage %s hostname\n", argv[0]);
      exit(0);
   }
   //port_number = atoi(argv[2]);
   socket_file_descriptor = socket(AF_INET, SOCK_STREAM, 0);

   if (socket_file_descriptor < 0)
       error("ERROR opening socket");

   server = gethostbyname(argv[1]);

   if (server == NULL) {
       fprintf(stderr,"ERROR, no such host\n");
       exit(0);
   }

   bzero((char *) &server_address, sizeof(server_address));
   server_address.sin_family = AF_INET;
   bcopy((char *)server->h_addr,
        (char *)&server_address.sin_addr.s_addr, //this is just a long
        server->h_length);
   server_address.sin_port = htons(sender_port_number);

   if (connect(socket_file_descriptor,
       (struct sockaddr *)&server_address,
       sizeof(server_address)) < 0)
       error("ERROR connecting");

   printf("Please enter the message: ");
   bzero(buffer,256);
   fgets(buffer,255,stdin);
   n = write(socket_file_descriptor ,buffer,strlen(buffer));
   if (n < 0)
        error("ERROR writing to socket");
   bzero(buffer,256);
   n = read(socket_file_descriptor ,buffer,255);
   if (n < 0)
        error("ERROR reading from socket");
   printf("%s\n",buffer);
 } else {
   //printf("in parent thread\n");

   socket_file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
   if
     (socket_file_descriptor < 0) error("ERROR opening socket");

   bzero((char *) &server_address, sizeof(server_address));

   server_address.sin_family = AF_INET;
   server_address.sin_addr.s_addr = INADDR_ANY;
   server_address.sin_port = htons(reciever_port_number);

   if (bind(socket_file_descriptor, (struct sockaddr *) &server_address,
            sizeof(server_address)) < 0)
     error("ERROR on binding");

   listen(socket_file_descriptor,5);
   int client_length = sizeof(client_address);
   accept_file_descriptor = accept(socket_file_descriptor, (struct sockaddr *) &client_address, &client_length);
   if (accept_file_descriptor < 0)
     error("ERROR on accept");

   bzero(buffer,256);
   num_chars = read(accept_file_descriptor,buffer,255);
   if (num_chars < 0) error("ERROR reading from socket");
   printf("Here is the message: %s\n",buffer);

   if (write(accept_file_descriptor,"I got your message",18) < 0)
     error("ERROR writing to socket");
   return 0;
 }
 return 0;
}
