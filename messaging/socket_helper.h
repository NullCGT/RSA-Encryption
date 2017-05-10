//Accepts the socket connection made by the connect_to_server method. Called
//after the server gets the initial request from the client
//@returns
//    0 on success
//   -1 on failure
int accept_connection(int sockfd, struct sockaddr_in cl_addr);

//Binds the socket to the IP adddress and Port.
//@returns
//   void
void bind_me(int sockfd, char* ip);

//Connects to a server given the socket to use and the ip address of the server.
//@returns
//   sockaddr_in struct which contains the connected socket
struct sockaddr_in connect_to_server(int sockfd, char* ip);

//Creates a socket
//@returns
//  0 on success
//  1 on failure
int create_socket();
