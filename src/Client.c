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
    Random random;
    ServerDone *server_done;
    ClientKeyExchange server_key_exchange, client_key_exchange;
    Certificate *certificate;
    CertificateRequest *certificate_request;
    Finished finished, *server_finished;
    
	int  timestep;
    printf("client avviato\n");
    int phase = 0;
    
    
    //CLIENT STEPS
    timestep = 0;
    talker = client;    //initialise client
	
    ///////////////////////////////////////////////////////////////PHASE 1//////////////////////////////////////////////////////////
    //COSTRUZIONE CLIENT HELLO
    random.gmt_unix_time = (uint32_t)time(NULL); //TODO: rivedere se è corretto
    RAND_bytes(random.random_bytes, 28);
    
    
    client_hello.length = 69;
    client_hello.version = 3;
    client_hello.random = &random;
    client_hello.type = CLIENT_HELLO;

	client_hello.sessionId = 32;
    client_hello.ciphersuite = lista; //TODO: dobbiamo fare in modo da caricarle da file -> rivedere pure la lenght
				
    //WRAPPING
    handshake = ClientServerHelloToHandshake(&client_hello);
    record = HandshakeToRecordLayer(handshake);
                
    //INVIAMO e APRIAMO LA COMUNICAZIONE AL SERVER
    OpenCommunication(client);
    sendPacketByte(record);
    printf("ClientHello sent!!!\n");
    OpenCommunication(server);
    
    while(CheckCommunication() == server){}
    
    server_message = readchannel();
    server_handshake = RecordToHandshake(server_message);
    server_hello = HandshakeToClientServerHello(server_handshake);//SERVER HELLO
    printf("ServerHello read!!!\n	CipherSuite:%02X\n", server_hello->ciphersuite->code);
    
    ///////////////////////////////////////////////////////////////PHASE 2//////////////////////////////////////////////////////////
    OpenCommunication(server);
    phase = 2;
    while(phase == 2){
        while(CheckCommunication() == server){}
        
        server_message = readchannel();
        server_handshake = RecordToHandshake(server_message);
        
        switch (server_handshake->msg_type) {
            case CERTIFICATE:
                certificate = HandshakeToCertificate(server_handshake);
            	printf("Certificate read\n");
                OpenCommunication(server);
                break;
            case SERVER_KEY_EXCHANGE:
                printf("Server Key Exchange read\n");
                OpenCommunication(server);
                break;
            case CERTIFICATE_REQUEST:
                certificate_request = HandshakeToCertificateRequest(server_handshake);
                printf("CertificateRequest read\n");
                OpenCommunication(server);
                break;
            case SERVER_DONE:
                phase = 3;
                break;
            default:
                perror("ERROR: Unattended message in phase 2.\n");
                exit(1);
                break;
        }
    
    }
    
    ///////////////////////////////////////////////////////////////PHASE 3//////////////////////////////////////////////////////////
    while(phase == 3){
        //CERTIFICATE
        printf("PHASE 33333\n");
		//CLIENT_KEY_EXCHANGE
        printf("client key exchange.\n");
    	//TODO
        
        //CERTIFICATE_VERIFY
    	//OpenCommunication(server);
        
        //while(CheckCommunication() == server){};
        phase = 4;
    }
    
    ///////////////////////////////////////////////////////////////PHASE 4//////////////////////////////////////////////////////////
        
    RAND_bytes(finished.hash, 36);
    handshake = FinishedToHandshake(&finished);
    record = HandshakeToRecordLayer(handshake);
        
    sendPacketByte(record);
    printf("client finished sent.\n");
    OpenCommunication(server);
    while(CheckCommunication() == server){};
    
    server_message = readchannel();
    server_handshake = RecordToHandshake(server_message);
    server_finished = HandshakeToFinished(server_handshake);
    printf("server finished read.\n");
    
    return 0;
    
}