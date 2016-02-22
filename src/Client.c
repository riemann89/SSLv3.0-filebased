#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "SSL_functions.h"

int main(int argc, const char *argv[]){
    printf("%lu\n",sizeof(uint8_t));
    uint32_t a=2;
    uint8_t b;
    b=a;
    printf("%02x",b);
}
