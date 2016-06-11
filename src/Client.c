#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "SSL_functions.h"


int main(int argc, const char *argv[]){
    //VARIABLE DECLARATION
    
    Talker client;
    int  timestep=0;
    Random ran;
    ClientServerHello client_hello,*client_hello_p;
    Handshake *handshake;
    RecordLayer *recordlayer;
    
    printf("ciao");
    X509* test;
    test = loadCertificate("server.crt");
    
    
    //CLIENT STEPS
    client=0;    //initialise client
	
    OpenCommunication(client);
	
    while(timestep<2){
        
        if(CheckCommunication()==client){
            
            if(timestep==0){

                ran.gmt_unix_time=35; // ???????????????
                
                for(int i=0;i<28;i++){
                    ran.random_bytes[i]=(uint8_t) i;
                }
                client_hello.random=ran;
                client_hello.sessionId=55;
                client_hello.version=3;
                client_hello.ciphersuite=lista;
                client_hello.length=69;
                
                client_hello_p=&client_hello; //
 
                handshake = ClientServerHelloToHandshake(client_hello_p);
				
                recordlayer=HandshakeToRecordLayer(handshake);
				
                sendPacketByte(recordlayer);
                
                //ora ho mandato il clienthello  passo il turno al server in attesa di risposta
            }
            
            else if(timestep==1){
                
                ClientServerHello *serverhello;
                serverhello=readchannel();
                printf("\n scelto l'algoritmo: %02x", serverhello->ciphersuite[0].code );
                
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