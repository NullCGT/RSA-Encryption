int accept_connection(int sockfd, struct sockaddr_in cl_addr);
void bind_me(int sockfd, char* ip);
struct sockaddr_in connect_to_server(int sockfd, char* ip);
int create_socket();
