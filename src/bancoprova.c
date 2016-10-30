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

void setPriorities(uint8_t *number, uint8_t *priority, char *filename);
int main(int argc, const char *argv[]){
    
   
   
    
   uint8_t prioritylen = 7;
   uint8_t *priority = NULL;
   
   
   /* come fare altre liste
    * si può capire dal codice sotto usato per creare le liste già in essere
    * nello specifico:
    * inserire nell array priority un numero a piacere di chipher codes, settare prioritylen di conseguenza
    * setPriorities(&prioritylen,priority, "percorso/PriorityNumeroSequenziale.txt")
    * compilare ed eseguire :)
    */
    int i;
    for (i = 0; i < prioritylen; i++) {
        priority[i]=i+12;
    }
    priority[0]= 5;
   
    setPriorities(&prioritylen, priority, "ServerConfig/Priority1.txt");
    
    
    prioritylen = 9;
      for (i = 0; i < prioritylen; i++) {
        priority[i]=i+18;
    }
   
    setPriorities(&prioritylen, priority, "ServerConfig/Priority2.txt");
    
    
    prioritylen = 5;
      for (i = 0; i < prioritylen; i++) {
        priority[i]=i+2;
    }
   
    setPriorities(&prioritylen, priority, "ServerConfig/Priority3.txt");
    
   
    prioritylen = 16;
      for (i = 0; i < 10; i++) {
        priority[i]=i;
    }
    for(i=10;i<16;i++){
        priority[i]=i+6;
    }
   
    setPriorities(&prioritylen, priority, "ServerConfig/All.txt");
    
    
     prioritylen = 7;
      for (i = 0; i < prioritylen; i++) {
        priority[i]=i+21;
    }
   
    setPriorities(&prioritylen, priority, "ClientConfig/Priority1.txt");
    
     prioritylen = 5;
      for (i = 0; i < prioritylen; i++) {
        priority[i]=i+18;
    }
   
    setPriorities(&prioritylen, priority, "ClientConfig/Priority2.txt");
    
     prioritylen = 15;
      for (i = 0; i < prioritylen; i++) {
        priority[i]=i+3;
    }
   
     
    setPriorities(&prioritylen, priority, "ClientConfig/Priority3.txt");
    
   return 0;
}


/**
 * write on the file named *filename the list of chiphersuite *priority coded as uint8_t which length is *number,
 * the list *priority should be sorted in decrescent order of priority.
 * @param uint8_t *number
 * @param uint8_t *priority
 * @param char *filename
 */
void setPriorities(uint8_t *number, uint8_t *priority, char *filename){
    
    FILE* PriorityList;
    
    PriorityList = fopen(filename , "wb");
    fwrite(number,sizeof(uint8_t),1,PriorityList);
    
    for(int i = 0; i<*number; i++){
        fwrite(priority +i,sizeof(uint8_t),1,PriorityList);
    }
    fclose(PriorityList);
}

