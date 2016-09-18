#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rand.h>
#include "SSL_functions.h"


int main(int argc, const char *argv[]){
    //VARIABLE DECLARATION
    
    Talker talker;
    
    ClientServerHello client_hello, *server_hello;
    Handshake *handshake, *server_handshake;
    RecordLayer *record, *server_message;
    ServerDone *server_done;
    ClientKeyExchange client_key_exchange;
    
	int  timestep;
    printf("ciao\n");
    int phase = 0;
    
    //CLIENT STEPS
    timestep = 0;
    talker = client;    //initialise client
	
    ///////////////////////////////////////////////////////////////PHASE 1//////////////////////////////////////////////////////////
    OpenCommunication(client);

    //COSTRUZIONE CLIENT HELLO
    client_hello.length = 69;
    client_hello.version = 3;
    client_hello.random->gmt_unix_time=(uint32_t)time(NULL); //TODO: rivedere se è corretto
    RAND_bytes(client_hello.random->random_bytes, 28);
	client_hello.sessionId = 0;
    client_hello.ciphersuite = lista; //TODO: dobbiamo fare in modo da caricarle da file -> rivedere pure la lenght
				
    //WRAPPING
    handshake = ClientServerHelloToHandshake(&client_hello);
    record = HandshakeToRecordLayer(handshake);
                
    //INVIAMO e APRIAMO LA COMUNICAZIONE AL SERVER
    sendPacketByte(record);
    phase = 1;
    
    OpenCommunication(server);
    while(CheckCommunication() == server)
    
    server_message = readchannel();
    server_handshake = RecordToHandshake(server_message);
    server_hello = HandshakeToClientServerHello(server_handshake);//SERVER HELLO
    
    OpenCommunication(server);
    while(CheckCommunication() == server)
        
    //SERVER DONE
    server_message = readchannel();
    server_handshake = RecordToHandshake(server_message);
    server_done = HandshakeToServerdone(server_handshake);
    
	//CLIENT_KEY_EXCHANGE
    //TODO
    
    OpenCommunication(server);
    while(CheckCommunication() == server);
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    return 0;
    
}