#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>


// server implementation: http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/socket.html

#define port_number 57777

void error(char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
  int socket_file_descriptor, accept_file_descriptor;

  char buffer[256];
  struct sockaddr_in server_address, client_address;
  int num_chars;

  socket_file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if
    (socket_file_descriptor < 0) error("ERROR opening socket");

  bzero((char *) &server_address, sizeof(server_address));

  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = INADDR_ANY;
  server_address.sin_port = htons(port_number);

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
