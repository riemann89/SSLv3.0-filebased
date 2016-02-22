#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){

    Random ran;
    ran.gmt_unix_time=35;
    uint8_t array[28]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28};
    ran.random_bytes=array; //QUI NON RUNNA PERCHE' ABBIAMO CAMBIATO IL PUNTATORE DEL RANDOM ToDo
    ClientServerHello cli;
    ClientServerHello* p_cli;
    p_cli=&cli;
    cli.random=ran;
    cli.sessionId=55;
    cli.version=3;
    cli.ciphersuite=lista;
    cli.length=69;
    
    //Handshake
    Handshake *handshake;
    //
    
    handshake=ClientServerHelloToHandshake(p_cli);
    RecordLayer *recordlayer;
    recordlayer=HandshakeToRecordLayer(handshake);
    
    sendPacket(*recordlayer);
    
    /*
    for(int i=0;i<(handshake->length);i++){
        printf("%02x",*(recordlayer->message+i));
    }
    printf("\n");
    */
    
    return 0;
}
