#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    
	//semaforo provo  a comunicare
FILE* canaleSSL;
char a='c';

	OpenCommunication(client);
		int i=0;
    while(i<5){
		if(CheckCommunication()==client){
			OpenCommunication(server);
			i++;
	    canaleSSL=fopen("canaleSSL.txt", "a+");
		fprintf(canaleSSL,"%c",a);
        fclose(canaleSSL);
		
		}
		
	}
	
	
    
    return 0;
}
