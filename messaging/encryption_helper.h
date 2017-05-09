#include "structs.h"

//Creates an RSA key by seeding the random number generator with an ip address
//@returns
//   RSA*
RSA* do_bad_things(char* ip_address);

//Enrypts message using the RSA token
//@returns
//   char*
char *encryption(RSA* keypair_pub, char* message);

//Handles the encryption of our package. Encrypts the IP adddresses in multiple layers
//@returns
//   tosend_t
tosend_t struct_encryption(node_t* relay_data, tosend_t package, RSA* pub_for_final);

//Handles the decryption of our package. Decrypts one entire layer of IP addresses.
//@returns
//   tosend_t
tosend_t struct_decryption(RSA* keypair, tosend_t package, int encrypt_len);

//Reads a list of IP addresses from the input file and generates RSA keys based on them 
//@returns
//   node_t*
node_t* read_file();
