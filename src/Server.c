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
#include <openssl/dh.h>
#include <openssl/bn.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    //Declaration
    ClientServerHello server_hello, *client_hello;
    Handshake *handshake, *client_handshake;
    RecordLayer *record, *client_message, *temp;
    ClientKeyExchange *client_key_exchange;
    Random random;
    Certificate *certificate;
    CertificateVerify *certificate_verify;
    Finished finished;
    uint8_t priority[10];
    CipherSuite *ciphersuite_choosen;
    CertificateType certificate_type;
    int phase, key_block_size, len_parameters;
    //char certificate_string[100];
    uint8_t prioritylen, ciphersuite_code, *pre_master_secret, *master_secret,*sha_1,*md5_1, *sha_fin, *md5_fin, *enc_message;
    MD5_CTX md5;
    SHA_CTX sha;
    uint32_t sender_var ,*sender;
    uint8_t *cipher_key;
    uint8_t *key_block;

    
    //Initialization
    master_secret = NULL;
    cipher_key = NULL;
    key_block = NULL;
    certificate = NULL;
    ciphersuite_code = 0; //TODO come mai questi valori?
    prioritylen = 10;
    phase = 0;
    certificate_type = 0;
    
    SHA1_Init(&sha);
    MD5_Init(&md5);
    
    ///////////////////////////////////////////////////////////////PHASE 1//////////////////////////////////////////////////////////
    
    printf("!!!SERVER AVVIATO!!!\n");
    
    while(CheckCommunication() == client){}
    client_message = readchannel();
    
    printf("\nCLIENT_HELLO: read\n");
    for(int i=0; i<client_message->length - 5; i++){
        printf("%02X ", client_message->message[i]);       
    }
    printf("\n\n");
    
    //TODO: inserire controllo sul pacchetto
    
    SHA1_Update(&sha,client_message->message,sizeof(uint8_t)*(client_message->length-5));
    MD5_Update(&md5,client_message->message,sizeof(uint8_t)*(client_message->length-5));

    client_handshake = RecordToHandshake(client_message);
    client_hello = HandshakeToClientServerHello(client_handshake);
    
    sender_var= client_hello->sessionId; //TODO: errore ID (vedi /Documents/TODO.txt)
    sender = &sender_var;
   
    //Cipher choosing TODO: rivedere
    int i;
    for (i = 0; i < 10; i++) {
        priority[i] = i+12;
    }
    priority[0] = 5;
    setPriorities(&prioritylen, priority, "ServerConfig/Priority1.txt");
    ciphersuite_code = chooseChipher(client_hello, "ServerConfig/Priority1.txt");
    printf("%02X", ciphersuite_code);
    
    //Construction Server Hello
    random.gmt_unix_time = (uint32_t)time(NULL); //TODO: rivedere se è corretto
    RAND_bytes(random.random_bytes, 28);
    
    server_hello.type = SERVER_HELLO;
    server_hello.length = 39;
    server_hello.version = 3;
    server_hello.random = &random;
    server_hello.sessionId = 32; //TODO: da sistemare
    server_hello.ciphersuite_code = &ciphersuite_code;
				
    //Wrapping
    handshake = ClientServerHelloToHandshake(&server_hello);
    record = HandshakeToRecordLayer(handshake);
    
    printf("\nSERVER_HELLO: sent\n");
    for(int i=0; i<record->length - 5; i++){
        printf("%02X ", record->message[i]);        
    }
    printf("\n\n");
    
    SHA1_Update(&sha,record->message,sizeof(uint8_t)*(record->length-5));
    MD5_Update(&md5,record->message,sizeof(uint8_t)*(record->length-5));
    
    //ciphersuite_choosen = CodeToCipherSuite(ciphersuite_code); TODO: eliminare la riga dopo usata per i test
    ciphersuite_choosen = CodeToCipherSuite(0x11); //TODO: riga su...
    certificate_type = CodeToCertificateType(0x11);//TODO: automatizzare
	
    
    printf("%d\n", certificate_type);
    //Sending server hello and open the communication to the client.
    sendPacketByte(record);
    OpenCommunication(client);
    
    ///////////////////////////////////////////////////////////////PHASE 2//////////////////////////////////////////////////////////
    while(CheckCommunication() == client){}
    
    
    //CERTIFICATE

	//TODO: gestire gli altri certificati
    
    if (certificate_type !=DH_ANON) {
        
    	switch (certificate_type) {
        	case RSA_SIGN:
                //strcpy((char*)&certificate_string, "certificates/RSA_server.crt");
            	certificate = loadCertificate("certificates/RSA_server.crt");
            	break;
            case DSS_SIGN:
                break;
            case RSA_FIXED_DH:
                break;
            case DSS_FIXED_DH:
                break;
            case RSA_EPHEMERAL_DH:
                break;
            case DSS_EPHEMERAL_DH:
                certificate = loadCertificate("certificates/DSA_server.crt");
                break;
            case DH_ANON:
                break;
            case FORTEZZA_MISSI:
                break;
        	default:
                perror("Certificate type error.");
                exit(1);
            	break;
        }

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
    
    if (certificate_type != RSA_SIGN && certificate_type != RSA_FIXED_DH && certificate_type != DSS_FIXED_DH){
        
        //generare i parametri di diffie-helmann
        DH *dh;
        
        dh = DH_new();//TODO: remember to free
        
        if (DH_generate_parameters_ex(dh, 2048, 2, NULL) == 0){
            perror("DH parameter generation error.");
            exit(1);
        };
        
        int error_codes = 0;
        
        if(DH_check(dh, &error_codes) == 0){
            perror("DH parameter check not passed.");
            exit(1);
        }
		
        if(DH_generate_key(dh) == 0){
            perror("DH keys generarion error.");
            exit(1);
        }

        ServerKeyExchange server_key_exchange;
        
        server_key_exchange.len_parameters = 3*DH_size(dh);
        server_key_exchange.parameters = (uint8_t*)calloc(server_key_exchange.len_parameters, sizeof(uint8_t));
        server_key_exchange.signature = (uint8_t*)calloc(ciphersuite_choosen->signature_size, sizeof(uint8_t));
        
        BN_bn2bin(dh->p, server_key_exchange.parameters);
        BN_bn2bin(dh->g, server_key_exchange.parameters + BN_num_bytes(dh->p));
        BN_bn2bin(dh->pub_key, server_key_exchange.parameters + 2*BN_num_bytes(dh->p));
        
        //TODO: salvare p,g nel codice o su file.
        
        //creare la firma
        
        //impacchettare
        
        //spedire e mettersi in attesa
        handshake = ServerKeyExchangeToHandshake(&server_key_exchange, ciphersuite_choosen);
        record = HandshakeToRecordLayer(handshake);
        
        printf("\nSERVER KEY EXCHANGE: sent\n");
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
                    printf("%d\n", client_handshake->length);
                    len_parameters = client_handshake->length - 4;
                    printf("%d\n",len_parameters);
                    client_key_exchange = HandshakeToClientKeyExchange(client_handshake, ciphersuite_choosen);

                    printf("\nCLIENT_KEY_EXCHANGE: recived\n");
                        for(int i=0; i<client_message->length - 5; i++){
                        printf("%02X ", client_message->message[i]);
                        }
                    printf("\n\n");
                    
                    SHA1_Update(&sha,client_message->message,sizeof(uint8_t)*(client_message->length-5));
                    MD5_Update(&md5,client_message->message,sizeof(uint8_t)*(client_message->length-5));
					
                    int out_size = 0;
                    pre_master_secret = decryptPreMaster(RSA_, client_key_exchange->parameters, len_parameters ,&out_size);
                    
                    master_secret = calloc(48, sizeof(uint8_t));
                    master_secret = MasterSecretGen(pre_master_secret, client_hello, &server_hello);

                    printf("\nMASTER KEY:generated\n");
                    for (int i=0; i< 48; i++){
                        printf("%02X ", master_secret[i]);
                    }
                    printf("\n");
                    
                    //KEYBLOCK GENERATION
                    key_block = KeyBlockGen(master_secret, ciphersuite_choosen, &key_block_size, client_hello, &server_hello);
                    
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
                   printf("\nCERTIFICATE_VERIFY: received\n");
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
    
	int dec_message_len = 0;
    uint8_t *dec_message = NULL;
    
    printf("%d/n", client_message->length);
    
    dec_message = DecEncryptPacket(client_message->message, client_message->length - 5, &dec_message_len, ciphersuite_choosen, key_block, client, 0);
    
    dec_message_len = 40; //TODO
    
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
    
    SHA1_Update(&sha, pad_1,sizeof(uint8_t)*40);
    MD5_Update(&md5, pad_1,sizeof(uint8_t)*48);
    
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
    int enc_message_len = 0;
    
    enc_message = DecEncryptPacket(temp->message, temp->length - 5, &enc_message_len, ciphersuite_choosen, key_block, server, 1);
    
    // assembling encrypted packet
    record = calloc(1, sizeof(RecordLayer));
    record->length = enc_message_len + 5; //TODO
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
