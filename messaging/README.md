This program allows users to chat with one another anonymously. It does this through a system that is modeled of TOR and 
onion routing: It encrypts the data to be sent in several layers of encryption and passes it through several intermediary 
servers to the receiver. The intermediary servers each strip off a layer of encryption, and do not know the identity of the 
receiver or the sender. Encryption is done using the open SSL library 

** to compile the code simply run make 
** to execute as a client (computer sending the initial message) run tcpclient param1 param2 param3 
                                                                                  |     |       |
                                                                             receiver's ip address
                                                                                        |       |
                                                                                     number of layers to encrypt the ip(min 3)
                                                                                                |
                                                                                             initial message to send

** computers acting as intermediary servers, as well as the final receiver need to run tcpclient withour parameters   




