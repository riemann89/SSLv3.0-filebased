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
    CipherSuite priority[10], choosen;
    uint8_t prioritylen=10,choice, *pre_master_secret, *master_secret;
    RSA *rsa_private_key = NULL;
    
    
    printf("Server started.\n");
    int phase = 0;
    
    //CLIENT STEPS
    
    ///////////////////////////////////////////////////////////////PHASE 1//////////////////////////////////////////////////////////
    while(CheckCommunication() == client){}
    client_message = readchannel();
    
    printf("\nCLIENT_HELLO: read\n");
    for(int i=0; i<client_message->length - 5; i++){
        printf("%02X ", client_message->message[i]);
        
    }
    printf("\n\n");
    
    client_handshake = RecordToHandshake(client_message);
    client_hello = HandshakeToClientServerHello(client_handshake);
   
    //SELEZIONO LA CIPHER PIU' APPROPRIATA
    int i;
    for (i = 0; i < 10; i++) {
        priority[i].code=i+12;
    }
    setPriorities(&prioritylen,priority);
    choosen.code = chooseChipher(client_hello);
    //COSTRUZIONE SERVER HELLO
    random.gmt_unix_time = (uint32_t)time(NULL); //TODO: rivedere se è corretto
    RAND_bytes(random.random_bytes, 28);
    
    server_hello.type = SERVER_HELLO;
    server_hello.length = 39;
    server_hello.version = 3;
    server_hello.random = &random;
    server_hello.sessionId = 32;
    server_hello.ciphersuite = &choosen; //TODO: dobbiamo fare in modo da caricarle da file -> rivedere pure la lenght
				
    //WRAPPING

    handshake = ClientServerHelloToHandshake(&server_hello);
    record = HandshakeToRecordLayer(handshake);
    
    printf("\nSERVER_HELLO: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);
        
    }
    printf("\n\n");
    
    //INVIAMO IL SERVERHELLO e APRIAMO LA COMUNICAZIONE AL SERVER
    sendPacketByte(record);
    OpenCommunication(client);
    
    ///////////////////////////////////////////////////////////////PHASE 2//////////////////////////////////////////////////////////
    while(CheckCommunication() == client){}
    
    
    //CERTIFICATE send the certificate for the chosen cipher
    certificate = loadCertificate("certificates/RSA_server.crt");
    handshake = CertificateToHandshake(certificate);
    record = HandshakeToRecordLayer(handshake);
      
    printf("\nCERTIFICATE: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);
        
    }
    printf("\n\n");
       
    sendPacketByte(record);
    OpenCommunication(client);
    while(CheckCommunication() == client){}
    
    //SERVER KEY EXCHANGE
    
    //CERTIFICATE REQUEST
    
    //SERVER HELLO DONE end this pahse,waiting for the master key
    handshake = ServerDoneToHandshake();
    record = HandshakeToRecordLayer(handshake);
   
    printf("\nSERVER_DONE: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);
        
    }
    printf("\n\n");
    
    sendPacketByte(record);
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
                 printf("\nCERTIFICATE: recived\n");
                    for(int i=0; i<client_message->length - 5; i++){
                         printf("%02X ", client_message->message[i]);
            
                         }
                printf("\n\n");
                OpenCommunication(client);
                break;
            case CLIENT_KEY_EXCHANGE:
                client_key_exchange = HandshakeToClientKeyExchange(client_handshake, RSA_, 128);
                
                printf("\nCLIENT_KEY_EXCHANGE: recived\n");
                    for(int i=0; i<client_message->length - 5; i++){
                    printf("%02X ", client_message->message[i]);       
                    }
                printf("\n\n");
                               
                //Estraggo chiave privata
                //rsa_private_key = RSA_new();
                FILE * fp = fopen("certificates/RSA_server.key","rb"); // aggiungere un controllo
                
                if (fp == NULL){
                    printf("PUNTATORE A NULLO");
                }
                rsa_private_key = NULL;
                rsa_private_key = (RSA*)PEM_read_RSAPrivateKey(fp, &rsa_private_key, NULL, NULL);
                
                //Dato in chiaro
                pre_master_secret = (uint8_t*)calloc(48, sizeof(uint8_t));
                
                RSA_private_decrypt(128, client_key_exchange->parameters,
                                        pre_master_secret, rsa_private_key, RSA_PKCS1_PADDING);
                
                //TODO: RSA_free(rsa_private_key);
                
                printf("PRE-MASTER KEY:extracted\n");
                for (int i=0; i< 48; i++){
                    printf("%02X ", pre_master_secret[i]);
                }
                printf("\n\n");
                OpenCommunication(client);
                break;
            case CERTIFICATE_VERIFY:
                certificate_verify = HandshakeToCertificateVerify(client_handshake);
               printf("\nCERTIFICATE_VERIFY: recived\n");
                    for(int i=0; i<client_message->length - 5; i++){
                    printf("%02X ", client_message->message[i]);       
                    }
                printf("\n\n");
                OpenCommunication(client);
                break;
            case FINISHED:
                phase = 4;
                printf("\nFINISHED: recived\n");
                    for(int i=0; i<client_message->length - 5; i++){
                    printf("%02X ", client_message->message[i]);       
                    }
                printf("\n\n");
                master_secret = calloc(48, sizeof(uint8_t));
                master_secret = MasterSecretGen(pre_master_secret, client_hello, &server_hello);
                
                printf("\nMASTER KEY:generated\n");
                for (int i=0; i< 48; i++){
                    printf("%02X ", master_secret[i]);
                }
                printf("\n");

                
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
    
      printf("\nFINISHED: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);
        
    }
    printf("\n\n");
    
    sendPacketByte(record);
    OpenCommunication(client);
    printf("tutto e' compiuto..!\n");

   	
	return 0;
}