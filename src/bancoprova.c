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
    
    ClientServerHello hello;
    CipherSuite test1, test2, test3;
    test1.code=18;
    test2.code=30;
    test3.code=29;
    
   printf("test1: %u\n test2: %u\ntest3: %u\n",getAlgorithm(test1),getAlgorithm(test2),getAlgorithm(test3));
   return 0;
    
}