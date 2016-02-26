#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    
    bool a=CheckCommunication();
    printf("%d\n",a);
    return 0;
}
