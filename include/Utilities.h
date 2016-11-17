#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "structures.h"

void reverse(uint8_t originale[],int length);
void  int_To_Bytes(uint32_t t, uint8_t *t_Bytes);
uint32_t Bytes_To_Int(int len, uint8_t *t_Bytes);
uint8_t ByteCompare(uint8_t *first, uint8_t *second, uint8_t length);
void setPriorities(uint8_t *number, uint8_t *priority, char *filename);