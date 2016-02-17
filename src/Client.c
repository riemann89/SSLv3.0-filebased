//
//  main.c
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
    /*
    //Leggi configurazione:
    FILE* canaleSSL;
    char a='c';
    
    for (int i=0; i<10; i++) {
        while(CheckCommunication(1)!=0){
            usleep(100);
        };
        
        canaleSSL=fopen("canaleSSL.txt", "a+");
        if(canaleSSL == NULL) {
            perror("Errore in apertura del file");
            exit(1);
        }
        fprintf(canaleSSL,"%c",a);
        fclose(canaleSSL);
        
        OpenCommunicationServer();
    }
    OpenCommunicationClient();
    //SCRIVO
    
    
    //Hello Client
    //RecordProtocol(alert, 2);
     */
    
    //CipherSuite test={0x01,0x10};
    
    
    
    return 0;
}
