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
#include <openssl/md5.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    //VARIABLE DECLARATION
    ClientServerHello server_hello, *client_hello;
    Handshake *handshake, *client_handshake;
    RecordLayer *record, *client_message, *temp;
    ClientKeyExchange *client_key_exchange;
    Random random;
    Certificate *certificate;
    CertificateVerify *certificate_verify;
    Finished finished;
    CipherSuite priority[10], choosen;
    CipherSuite2 *cipher_suite_choosen;
    int phase, key_block_size;
    char certificate_string[100];
    uint8_t prioritylen, ciphersuite_code, *pre_master_secret, *master_secret,*sha_1,*md5_1, *sha_fin, *md5_fin, *enc_message;
    MD5_CTX md5;
    SHA_CTX sha;
    uint32_t sender_var ,*sender;
    uint8_t *cipher_key;
    uint8_t *key_block = NULL;

    
    //VARIABLE INITIALIZATION
    ciphersuite_code = 0;
    master_secret = NULL;
    prioritylen = 10;
    phase = 0;
    cipher_key = NULL;
    SHA1_Init(&sha);
    MD5_Init(&md5);
    
    //SERVER STARTS
    printf("Server started.\n");
    
    ///////////////////////////////////////////////////////////////PHASE 1//////////////////////////////////////////////////////////
    while(CheckCommunication() == client){}
    client_message = readchannel();
    
    printf("\nCLIENT_HELLO: read\n");
    for(int i=0; i<client_message->length - 5; i++){
        printf("%02X ", client_message->message[i]);       
    }
    printf("\n\n");
    
    SHA1_Update(&sha,client_message->message,sizeof(uint8_t)*(client_message->length-5));
    MD5_Update(&md5,client_message->message,sizeof(uint8_t)*(client_message->length-5));

    client_handshake = RecordToHandshake(client_message);
    client_hello = HandshakeToClientServerHello(client_handshake);
    
    sender_var= client_hello->sessionId;
    sender = &sender_var;
   
    //SELEZIONO LA CIPHER PIU' APPROPRIATA
    int i;
    for (i = 0; i < 10; i++) {
        priority[i].code=i+12;
    }
    priority[0].code = 5;
    setPriorities(&prioritylen,priority, "ServerConfig/Priority1.txt");
    choosen.code = chooseChipher(client_hello, "ServerConfig/Priority1.txt");
    ciphersuite_code = choosen.code;
    printf("%02X", ciphersuite_code);
    
    //COSTRUZIONE SERVER HELLO
    random.gmt_unix_time = (uint32_t)time(NULL); //TODO: rivedere se è corretto
    RAND_bytes(random.random_bytes, 28);
    
    server_hello.type = SERVER_HELLO;
    server_hello.length = 39;
    server_hello.version = 3;
    server_hello.random = &random;
    server_hello.sessionId = 32;
    server_hello.ciphersuite = &choosen;
				
    //WRAPPING
    handshake = ClientServerHelloToHandshake(&server_hello);
    record = HandshakeToRecordLayer(handshake);
    
    printf("\nSERVER_HELLO: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);        
    }
    printf("\n\n");
    
    SHA1_Update(&sha,record->message,sizeof(uint8_t)*(record->length-5));
    MD5_Update(&md5,record->message,sizeof(uint8_t)*(record->length-5));
    
    cipher_suite_choosen = CodeToCipherSuite(05);
    printf("%d\n",cipher_suite_choosen->cipher_algorithm);
    //INVIAMO IL SERVERHELLO e APRIAMO LA COMUNICAZIONE AL SERVER
    sendPacketByte(record);
    OpenCommunication(client);
    
    ///////////////////////////////////////////////////////////////PHASE 2//////////////////////////////////////////////////////////
    while(CheckCommunication() == client){}
    
    
    //CERTIFICATE
    if (ciphersuite_code == 0x05){ //TODO sistemare
        //TODO fare uno switch sui vari casi che trattiamo
        //strcpy((char*)&certificate_string, "certificates/RSA_server.crt");
    	certificate = loadCertificate("certificates/RSA_server.crt");
    	handshake = CertificateToHandshake(certificate);
    	record = HandshakeToRecordLayer(handshake);
      
    	printf("\nCERTIFICATE: sent\n");
    	for(int i=0; i<record->length - 5; i++){
        	printf("%02X ", record->message[i]);
    	}
    	printf("\n\n");
       
    	SHA1_Update(&sha,record->message,sizeof(uint8_t)*(record->length-5));
    	MD5_Update(&md5,record->message,sizeof(uint8_t)*(record->length-5));
    
    	sendPacketByte(record);
    	OpenCommunication(client);
    	while(CheckCommunication() == client){}
    }
    
    //SERVER KEY EXCHANGE
    
    //CERTIFICATE REQUEST
    
    //SERVER HELLO DONE
    handshake = ServerDoneToHandshake();
    record = HandshakeToRecordLayer(handshake);
   
    printf("\nSERVER_DONE: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);
        
    }
    printf("\n\n");
    
    SHA1_Update(&sha,record->message,sizeof(uint8_t)*(record->length-5));
    MD5_Update(&md5,record->message,sizeof(uint8_t)*(record->length-5));
    
    sendPacketByte(record);
    OpenCommunication(client);
    
    ///////////////////////////////////////////////////////////////PHASE 3//////////////////////////////////////////////////////////
    
    phase = 3;
    while(phase == 3){
        while(CheckCommunication() == client){}
        
        client_message = readchannel();
        //TODO: l'IF si può rimuovere
        if(client_message->type==HANDSHAKE){

            client_handshake = RecordToHandshake(client_message);
            switch (client_handshake->msg_type) {
                case CERTIFICATE:
                    certificate = HandshakeToCertificate(client_handshake);
                     printf("\nCERTIFICATE: received\n");
                        for(int i=0; i<client_message->length - 5; i++){
                             printf("%02X ", client_message->message[i]);

                             }
                    printf("\n\n");
                    OpenCommunication(client);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    client_key_exchange = HandshakeToClientKeyExchange(client_handshake, cipher_suite_choosen->key_exchange_algorithm, 128);//TODO 128 va letto dal certificato ed è la lunghezza della chiave in byte.

                    printf("\nCLIENT_KEY_EXCHANGE: recived\n");
                        for(int i=0; i<client_message->length - 5; i++){
                        printf("%02X ", client_message->message[i]);
                        }
                    printf("\n\n");
                    
                    SHA1_Update(&sha,client_message->message,sizeof(uint8_t)*(client_message->length-5));
                    MD5_Update(&md5,client_message->message,sizeof(uint8_t)*(client_message->length-5));
					
                    pre_master_secret = decryptPreMaster(RSA_, client_key_exchange->parameters);//TODO inizializzare RSA_ sopra
                    
                    master_secret = calloc(48, sizeof(uint8_t));
                    master_secret = MasterSecretGen(pre_master_secret, client_hello, &server_hello);

                    printf("\nMASTER KEY:generated\n");
                    for (int i=0; i< 48; i++){
                        printf("%02X ", master_secret[i]);
                    }
                    printf("\n");
                    
                    //KEYBLOCK GENERATION
                    key_block_size = 2*(cipher_suite_choosen->signature_size + cipher_suite_choosen->key_material + cipher_suite_choosen->iv_size);
                    printf("key block size: %d\n", key_block_size);
                    key_block = KeyBlockGen(master_secret, cipher_suite_choosen, client_hello, &server_hello);
                    
                    printf("\nKEY BLOCK\n");
                    for (int i=0; i< key_block_size; i++){
                        printf("%02X ", key_block[i]);
                    }
                    printf("\n");
                    phase = 4;//TODO: se usa il verify non funziona
                    OpenCommunication(client);

                    break;
                case CERTIFICATE_VERIFY:
                    certificate_verify = HandshakeToCertificateVerify(client_handshake);
                   printf("\nCERTIFICATE_VERIFY: recived\n");
                        for(int i=0; i<client_message->length - 5; i++){
                        printf("%02X ", client_message->message[i]);       
                        }
                    printf("\n\n");
                    
                    SHA1_Update(&sha,client_message->message,sizeof(uint8_t)*(client_message->length-5));
                    MD5_Update(&md5,client_message->message,sizeof(uint8_t)*(client_message->length-5));
                    OpenCommunication(client);
                    break;
            	default:
                    printf("%02X\n", client_handshake->msg_type);
                    perror("ERROR: Unattended message in phase 3.\n");
                    exit(1);
                    break;
            }
        }
    }
    ///////////////////////////////////////////////////////////////PHASE 4//////////////////////////////////////////////////////////
    
    while(CheckCommunication() == client)
    client_message = readchannel();
    printf("\nCHANGE_CIPHER_SPEC: received\n");
    for(int i=0; i<client_message->length - 5; i++){
        printf("%02X ", client_message->message[i]);
    }
    printf("\n\n");
    
    OpenCommunication(client);
    while(CheckCommunication() == client){}
    
    client_message = readchannel();
    printf("\nFINISHED: received\n");
    for(int i=0; i<client_message->length - 5; i++){
        printf("%02X ", client_message->message[i]);
    }
    printf("\n\n");
    
	uint8_t dec_message_len = 40;
    uint8_t *dec_message = NULL;
    
    dec_message = calloc(40, sizeof(uint8_t));
    
    dec_message = DecEncryptPacket(client_message->message, client_message->length, &dec_message_len, cipher_suite_choosen, key_block, client, 0);
    
    printf("\nFINISHED DECRYPTED\n");
    for(int i=0; i < dec_message_len; i++){
        printf("%02X ", dec_message[i]);
    }
    printf("\n\n");

    
    record = ChangeCipherSpecRecord();
    sendPacketByte(record);
    
    printf("\nCHANGE_CIPHER_SPEC: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);
        
    }
    printf("\n\n");
    
    OpenCommunication(client);
    
    while(CheckCommunication() == client){}
    
    SHA1_Update(&sha,sender,sizeof(uint32_t));
    MD5_Update(&md5,sender,sizeof(uint32_t));
    
    SHA1_Update(&sha,master_secret,sizeof(uint8_t)*48);
    MD5_Update(&md5,master_secret,sizeof(uint8_t)*48);  
    
    SHA1_Update(&sha,pad_1,sizeof(uint8_t)*40);  
    MD5_Update(&md5,pad_1,sizeof(uint8_t)*48); 
    
    md5_1 = calloc(16, sizeof(uint8_t));
    sha_1 = calloc(20, sizeof(uint8_t));
    
    SHA1_Final(sha_1,&sha);
    MD5_Final(md5_1,&md5);
    
    SHA1_Init(&sha);
    MD5_Init(&md5);
    
    SHA1_Update(&sha, master_secret,sizeof(uint8_t)*48);
    SHA1_Update(&sha, pad_2,sizeof(uint8_t)*40);
    SHA1_Update(&sha, sha_1,sizeof(uint8_t)*20);
    
    MD5_Update(&md5, master_secret,sizeof(uint8_t)*48);
    MD5_Update(&md5, pad_2,sizeof(uint8_t)*48);
    MD5_Update(&md5, sha_1,sizeof(uint8_t)*16);
    
    md5_fin = calloc(16, sizeof(uint8_t));
    sha_fin = calloc(20, sizeof(uint8_t));
    
    SHA1_Final(sha_fin,&sha);
    MD5_Final(md5_fin,&md5);
    
    memcpy(finished.hash, md5_fin, 16*sizeof(uint8_t));
    memcpy(finished.hash + 16, sha_fin, 20*sizeof(uint8_t));
    
    /* MAC and ENCRYPTION*/
    
    handshake = FinishedToHandshake(&finished);
    /* MAC and ENCRYPTION*/
    temp = HandshakeToRecordLayer(handshake);
    
    // MANCA IL MAC
    uint8_t *enc_message_len = NULL;
    
    enc_message_len = calloc(1, sizeof(uint16_t));
    
    enc_message = DecEncryptPacket(temp->message, temp->length, enc_message_len, cipher_suite_choosen, key_block, server, 1);
    
    *enc_message_len = 45; //TODO: va fixato perchè me lo azzera
    
    // assembling encrypted packet
    record = calloc(1, sizeof(RecordLayer));
    record->length = *enc_message_len + 5; //TODO
    printf("lunghezza: %d\n", record->length);
    record->type = HANDSHAKE;
    record->version = std_version;
    record->message = enc_message;
    
    sendPacketByte(record);
    
    printf("\nFINISHED: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);
        
    }
    printf("\n\n");
    printf("tutto e' compiuto..!\n");
    
    OpenCommunication(client);

   	
	return 0;
}
