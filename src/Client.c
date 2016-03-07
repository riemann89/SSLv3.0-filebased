#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    
	//semaforo provo  a comunicare

//crea un clienthello e lo manda sul canale
	OpenCommunication(client);

   int  timestep=0;
	
	while(timestep<2){
	
			if(CheckCommunication()==client){    //controllo se posso parlare o meno
		
 			if(timestep==0){
		  Random ran;
    int i;
    ran.gmt_unix_time=35;
 
		for(i=0;i<28;i++){
    ran.random_bytes[i]=(uint8_t) i;
	}
    ClientServerHello cli;
    cli.random=ran;
    cli.sessionId=55;
    cli.version=3;
    cli.ciphersuite=lista;
    cli.length=69;
	
		
		
		
		ClientServerHello *client;
		client=&cli;
		
		Handshake *hand;
		hand= ClientServerHelloToHandshake(client);
		
		
		 RecordLayer *recordlayer;
         recordlayer=HandshakeToRecordLayer(hand);
    
		i=sendPacketByte(recordlayer);
		i=sendPacket(recordlayer);
		timestep=timestep+3;
		//ora ho mandato il clienthello  passo il turno al server in attesa di risposta
		}
		
		else if(timestep==1){
			printf("scelto l'algoritmo");
			
		}
		OpenCommunication(server);
		timestep++;

		}
	}
	
	
    /*while(i<5){
		if(CheckCommunication()==client){
			OpenCommunication(server);
			i++;
	    canaleSSL=fopen("canaleSSL.txt", "a+");
		fprintf(canaleSSL,"%c",a);
        fclose(canaleSSL);
		
		}
	
		 * */
		
	
	
	
    
    return 0;

}