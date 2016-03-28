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
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    
   /* char a='s';
    for (int i=0; i<10; i++) {
        while(CheckCommunication(0)!=0){
            usleep(100);
        };
        canaleSSL=fopen("canaleSSL.txt", "a+");
        if(canaleSSL == NULL) {
            perror("Errore in apertura del file");
            exit(1);
        }
        fprintf(canaleSSL,"%c",a);
        fclose(canaleSSL);
        
        OpenCommunicationClient();
    }
     */
    

	
	/*while(i<5){
		if(CheckCommunication()==server){
			OpenCommunication(client);
			i++;
			canaleSSL=fopen("canaleSSL.txt", "a+");
         fprintf(canaleSSL,"%c",a);
        fclose(canaleSSL);
			
		}
		
	}
	*/
	
	
    uint8_t  list[32];  //lunghezza massima  di liste supportate, list[0] = n° di cipher supportate "lunghezza vera della lista"
	uint8_t len = 10;
	
	for(int i = 0; i<len; i++){		   //carico le ciphre supportate dal server in ordine decrescente di priorità  (scelte a cazzo tanto per non avere lite banali di un solo elemento o di tutte le possibili chiphers)
		list[i] =  (uint8_t) (i +10);
	}
	
	list[30]=0;

setPriorities(len,list);    //setto la lista caricata
	
	// comincio la comunicazione
	  int  timestep=0;
	
	while(timestep<2){
	
			if(CheckCommunication()==server){    //controllo se posso parlare o meno
		
 			if(timestep==0){

				ClientServerHello *clienthello; 
			    clienthello=readchannel(); //leggo quello che è stato scritto dal client
				
				
				CipherSuite *choosen;  //lista da sostituire a quella del clienthello per completare il serverhello
				CipherSuite clientsuite;
				choosen=&clientsuite;
				clientsuite= get_cipher_suite(chooseChipher(clienthello));  //scelgo la miglior cifratura condivisa da server e client
				clienthello->ciphersuite=choosen;  //sostituisco alla lista con tutti le chiphers supportate da client la lista composta dalla sola cifratura scelta da server
				clienthello->length=39; //avrò una sola cipher
				
				//spedisco il tutto sul canale in attesa di client  
				Handshake hand;
				RecordLayer record;
				Handshake  *serverhand;    
				RecordLayer *serverRecord;
				serverhand=&hand;
				serverRecord=&record;
				
				serverhand=ClientServerHelloToHandshake(clienthello);
				serverRecord =HandshakeToRecordLayer(serverhand);
                sendPacketByte(serverRecord);   //pacchetto inviato!
	
		
		}
		
		else if(timestep==1){
			
			
			printf("\n ServerDone ");
			
		}
		OpenCommunication(client); //apro la comunicazione a client
		timestep++;

		}
	}
	
	
	
	
	return 0;
}