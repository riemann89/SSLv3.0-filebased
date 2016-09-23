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
    
   
   
    
   int prioritylen = 7;
   CipherSuite *priority;
   
    int i;
    for (i = 0; i < prioritylen; i++) {
        priority[i].code=i+12;
    }
    priority[0].code= 5;
   
    setPriorities(&prioritylen, priority, "ServerConfig/Priority1.txt");
    
    
    prioritylen = 9;
      for (i = 0; i < prioritylen; i++) {
        priority[i].code=i+18;
    }
   
    setPriorities(&prioritylen, priority, "ServerConfig/Priority2.txt");
    
    
    prioritylen = 5;
      for (i = 0; i < prioritylen; i++) {
        priority[i].code=i+2;
    }
   
    setPriorities(&prioritylen, priority, "ServerConfig/Priority3.txt");
    
   
     prioritylen = 7;
      for (i = 0; i < prioritylen; i++) {
        priority[i].code=i+21;
    }
   
    setPriorities(&prioritylen, priority, "ClientConfig/Priority1.txt");
    
     prioritylen = 5;
      for (i = 0; i < prioritylen; i++) {
        priority[i].code=i+18;
    }
   
    setPriorities(&prioritylen, priority, "ClientConfig/Priority2.txt");
    
     prioritylen = 15;
      for (i = 0; i < prioritylen; i++) {
        priority[i].code=i+3;
    }
   
     
    setPriorities(&prioritylen, priority, "ClientConfig/Priority3.txt");
    
   return 0;
}