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
    
    
    printf("Server avviato.\n");
    int phase = 0;
    
    //CLIENT STEPS
    
    ///////////////////////////////////////////////////////////////PHASE 1//////////////////////////////////////////////////////////
    while(CheckCommunication() == client){}
    client_message = readchannel();
    
    printf("\nRECORD RICEVUTO: ClientHello\n");
    printf("%02X ", client_message->type);
    printf("%04X ", client_message->length);
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
    printf("loaded priorities\n");
    setPriorities(&prioritylen,priority);
    //printf("ok settate\n");
    choosen.code = chooseChipher(client_hello);
    printf("scelta: %02X\n", choosen.code);
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
    printf("ready to send\n");
    handshake = ClientServerHelloToHandshake(&server_hello);
    printf("hand serverhello\n");
    record = HandshakeToRecordLayer(handshake);
    printf("serverhello sent\n");
    
    //INVIAMO IL SERVERHELLO e APRIAMO LA COMUNICAZIONE AL SERVER
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
                client_key_exchange = HandshakeToClientKeyExchange(client_handshake, RSA_, 128);
                
                printf("\nCLIENT_KEY_EXCHANGE RICEVUTO:\n");
                printf("%02X ", client_key_exchange->algorithm_type);
                printf("%08X ", client_key_exchange->len_parameters);
                for(int i=0; i<client_key_exchange->len_parameters; i++){
                    printf("%02X ", client_key_exchange->parameters[i]);
                    
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
                printf("questa è la chiave inizio\n:");
                
                printf("\n questa è la chiave fine:\n");
                //Dato in chiaro
                pre_master_secret = (uint8_t*)calloc(48, sizeof(uint8_t));
                
                RSA_private_decrypt(128, client_key_exchange->parameters,
                                        pre_master_secret, rsa_private_key, RSA_PKCS1_PADDING);
                
                //TODO: RSA_free(rsa_private_key);
                
                printf("PRE-MASTER KEY:");
                for (int i=0; i< 48; i++){
                    printf("%02X ", pre_master_secret[i]);
                }
                printf("\n");
                printf("Client Key Exchange read\n");
                OpenCommunication(client);
                break;
            case CERTIFICATE_VERIFY:
                certificate_verify = HandshakeToCertificateVerify(client_handshake);
                printf("CertificateRequest read\n");
                OpenCommunication(client);
                break;
            case FINISHED:
                phase = 4;
                master_secret = calloc(48, sizeof(uint8_t));
                master_secret = MasterSecretGen(pre_master_secret, client_hello, &server_hello);
                
                printf("MASTER KEY:");
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
    
    sendPacketByte(record);
    printf("client finished sent.\n");
    OpenCommunication(client);
    

   	
	return 0;
}