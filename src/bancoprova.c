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
#include <time.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    
	/*
	
	int filelen;
	uint8_t *buffer;
	FILE* SSLchannel;
	SSLchannel=fopen("SSLchannelbyte.txt", "r");
	
	
	ClientServerHello Reconstructed_Hello;
	ClientServerHello *returning_hello;
	returning_hello=&Reconstructed_Hello;
	
	filelen=ftell(SSLchannel);
	buffer = (uint8_t *)malloc((filelen+1)*sizeof(uint8_t));    // Enough memory for file + \0
    fread(buffer, 100, 1, SSLchannel);
	
	//returning_hello=(uint8_t*)calloc(100,sizeof(uint8_t));
	uint8_t  version=(uint8_t)*(buffer+9);
	uint8_t  length= (uint8_t)*(buffer +8) -4 + 1;  //tolgo i byte in più del handshake  (version + length) e aggiungo il byte di lunghezza
	
	uint8_t session[4];
	for(int i =0;i<4;i++){
	session[i]= *(buffer + 10 + i);
	}
	reverse(session,4);

	uint32_t  SessionId=(uint32_t)(session[0] + session[1] *256 + session[2]*256*256 + session[3]*256*256);
	
	
	Random ran;
	ran.gmt_unix_time=time(0);  //metto il tempo nuovo
	for (int i =0; i<28;i++){
	ran.random_bytes[i]=(uint8_t)*(buffer + 18 +i);
	}
	
	uint8_t  ciphers[length - 38]; //length of  ciphers
	for (int i =0; i<length -38;i++){
	ciphers[i]=(uint8_t)*(buffer + 18 +28 +i);
	}
	uint8_t *ciphers_ptr;
	ciphers_ptr=(uint8_t*)&ciphers;
	
	Reconstructed_Hello.version=version;
	Reconstructed_Hello.length=length;
	Reconstructed_Hello.sessionId=SessionId;
	Reconstructed_Hello.random=ran;
	Reconstructed_Hello.ciphersuite= (Cipher_Suite*)ciphers_ptr;
	
	printf("Length: %02x \n",Reconstructed_Hello.length);
	printf("Versione: %02x  \n",Reconstructed_Hello.version);
   	printf("Session: %02x \n",Reconstructed_Hello.sessionId);
	printf("Time: %02x \n",Reconstructed_Hello.random.gmt_unix_time);
	printf("\n RandomList: ");
	for(int i =0;i<28;i++){
		printf("%02x ",Reconstructed_Hello.random.random_bytes[i]);
	}
	
	printf("\n\n Ciphers: ");
	for(int i =0;i<length -38;i++){
		printf("%02x ",*(ciphers_ptr +i));
	}
	
	*/
	ClientServerHello *clientread;
	clientread=readchannel();
		
	printf("Length: %02x \n",clientread->length);
	printf("Versione: %02x  \n",clientread->version);
   	printf("Session: %02x \n",clientread->sessionId);
	printf("Time: %02x \n", clientread->random.gmt_unix_time);
	printf("\n RandomList: ");
	for(int i =0;i<28;i++){
		printf("%02x ",clientread->random.random_bytes[i]);
	}
	
	printf("\n\n Ciphers: ");
	
	//printf("\n\n OCIO: %02x \n\n", (uint8_t)clientread->ciphersuite);
	
	
	for(int i =0;i<clientread->length - 38; i++){
		
		
		printf("%02x ",clientread->ciphersuite[i].code);
	}
	
	//costruisco un file dove mettere in ordine di priorità i cipher da accettare, metto al primo posto quella con la maggior priorità e le altre a scalare.. non sono obbligato a metterle tutte e due
	

	uint8_t  list[32];  //lunghezza massima  di liste supportate, list[0] = n° di cipher supportate "lunghezza vera della lista"
	uint8_t len = 100;
	
	for(int i = 0; i<len; i++){		
		list[i] =  (uint8_t) (i +1);
	}
	
	list[30]=0;
	list[10]=0;

setPriorities(len,list);
	
	
	return 0;
}