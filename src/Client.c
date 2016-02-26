#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){


    
    //Handshake
    Handshake *handshake;
	Handshake hand;
	handshake=&hand;

  
   uint8_t arr[1];
   arr[0]=1;
  
   handshake=ServerDoneToHandshake();
  
 /* handshake->msg_type=SERVER_DONE;
   handshake->length=5;
   handshake->content=arr;
   */
   
   //=ServerHelloDoneToHandshake();  
	printf("serverhellodone done\n");
	
	
    RecordLayer *recordlayer;
    recordlayer=HandshakeToRecordLayer(handshake);
    
    sendPacket(recordlayer);
    

    return 0;
}
