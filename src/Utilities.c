#include "Utilities.h"

// funzioni comode
void reverse(uint8_t originale[],int length);
void  intToBytes(int i, uint8_t a[4]);
// codice

void reverse(uint8_t originale[],int length){  //take as input an array of Bytes and its length,  after this function is called your original vector will be reversed
	uint8_t reversed[length];
	int i;
	for(i=0; i<length;  i++){
		reversed[i]=originale[i];
	}
 for(i=0; i<length;   i++){ 
		originale[i]=reversed[length-i-1];
	}
}

void  intToBytes(int t, uint8_t *a){  //take as input an integer and an array of bytes  after this function is called the array will be the reversed Bytes representation of the integer
    int i;
	uint8_t *p=(uint8_t*) &t;
	for(i=0;i<4;i++){
		a[i]= *(p+i);
	}
	reverse(a,4);
}