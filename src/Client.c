#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    
    RecordLayer recordlayer_clienthello;
    ClientServerHello client_hello;
    recordlayer_clienthello.type=HANDSHAKE;
    recordlayer_clienthello.version.major=3;
    recordlayer_clienthello.version.minor=0;
    
    sendClient_Server_hello(recordlayer_clienthello,client_hello);
    

    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    return 0;
}
