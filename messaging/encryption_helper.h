#include "structs.h"

RSA* do_bad_things(char* ip_address);
char *encryption(RSA* keypair_pub, char* message);
tosend_t struct_encryption(node_t* relay_data, tosend_t package, RSA* pub_for_final);
tosend_t struct_decryption(RSA* keypair, tosend_t package, int encrypt_len);
node_t* read_file();
