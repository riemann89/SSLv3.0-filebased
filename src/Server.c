//
//  Server.c
//  SSLv3.0
//
//  Created by Giuseppe Giffone on 16/02/16.
//  Copyright © 2016 Giuseppe Giffone. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rand.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    printf("Server avviatoaaaa.\n");
    //VARIABLE DECLARATION
    ClientServerHello server_hello, *client_hello;
    Handshake *handshake, *client_handshake;
    RecordLayer *record, *client_message;
    ServerDone server_done;
    ClientKeyExchange *client_key_exchange;
    Random random;
    Certificate *certificate;
    CertificateVerify *certificate_verify;
    Finished *client_finished, finished;
    
    printf("Server avviato.\n");
    int phase = 0;
    
    //CLIENT STEPS
    
    ///////////////////////////////////////////////////////////////PHASE 1//////////////////////////////////////////////////////////
    while(CheckCommunication() == client){}
    client_message = readchannel();
    client_handshake = RecordToHandshake(client_message);
    client_hello = HandshakeToClientServerHello(client_handshake);
    printf("ClientHello read!!!\n	CipherSuite:%02X\n", client_hello->ciphersuite->code);
    
    //COSTRUZIONE SERVER HELLO
    random.gmt_unix_time = (uint32_t)time(NULL); //TODO: rivedere se è corretto
    RAND_bytes(random.random_bytes, 28);
    
    server_hello.type = SERVER_HELLO;
    server_hello.length = 45;
    server_hello.version = 3;
    server_hello.random = &random;
    server_hello.sessionId = 32;
    server_hello.ciphersuite = lista2; //TODO: dobbiamo fare in modo da caricarle da file -> rivedere pure la lenght
				
    //WRAPPING
    handshake = ClientServerHelloToHandshake(&server_hello);
    record = HandshakeToRecordLayer(handshake);
    
    //INVIAMO e APRIAMO LA COMUNICAZIONE AL SERVER
    sendPacketByte(record);
    printf("ServerHello sent!!!\n");
    OpenCommunication(client);
    
    ///////////////////////////////////////////////////////////////PHASE 2//////////////////////////////////////////////////////////
    while(CheckCommunication() == client){}
    
    
    //CERTIFICATE
    certificate = loadCertificate("certificates/RSA_server.crt");
    handshake = CertificateToHandshake(certificate);
    record = HandshakeToRecordLayer(handshake);
    
    sendPacketByte(record);
    printf("Certificate sent!!!\n");
    OpenCommunication(client);
    while(CheckCommunication() == client){}
    
    //SERVER KEY EXCHANGE
    
    //CERTIFICATE REQUEST
    
    //SERVER HELLO DONE
    handshake = ServerDoneToHandshake();
    record = HandshakeToRecordLayer(handshake);
    
    sendPacketByte(record);
    printf("ServerDone sent!!!\n");
    OpenCommunication(client);
    
    ///////////////////////////////////////////////////////////////PHASE 3//////////////////////////////////////////////////////////
    
    phase = 3;
    while(phase == 3){
        while(CheckCommunication() == client){}
        
        client_message = readchannel();
        client_handshake = RecordToHandshake(client_message);
        
        switch (client_handshake->msg_type) {
            case CERTIFICATE:
                certificate = HandshakeToCertificate(client_handshake);
                printf("Certificate read\n");
                OpenCommunication(client);
                break;
            case CLIENT_KEY_EXCHANGE:
                printf("Server Key Exchange read\n");
                OpenCommunication(client);
                break;
            case CERTIFICATE_VERIFY:
                certificate_verify = HandshakeToCertificateVerify(client_handshake);
                printf("CertificateRequest read\n");
                OpenCommunication(client);
                break;
            case FINISHED:
                phase = 4;
                client_finished = HandshakeToFinished(client_handshake);
                break;
            default:
                printf("%02X\n", client_handshake->msg_type);
                perror("ERROR: Unattended message in phase 3.\n");
                exit(1);
                break;
        }
    }
    
    ///////////////////////////////////////////////////////////////PHASE 4//////////////////////////////////////////////////////////
    RAND_bytes(finished.hash, 36);
    handshake = FinishedToHandshake(&finished);
    record = HandshakeToRecordLayer(handshake);
    
    sendPacketByte(record);
    printf("client finished sent.\n");
    OpenCommunication(client);

    
    
    

   	
	return 0;
}