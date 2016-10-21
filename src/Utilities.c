#include "Utilities.h"
/**
 * Take as input an array and its length and reverse it uo to the selected length
 * for example: reverse([1,2,3,4,5] ,4) -> [4,3,2,1,5]
 * @param *originale
 * @param int length
 */
void reverse(uint8_t originale[],int length){ 					 		
	uint8_t reversed[length];			                                                
	int i;
	for(i=0; i<length;  i++){
		reversed[i]=originale[i];														
	}
 for(i=0; i<length;   i++){ 
		originale[i]=reversed[length-i-1];										
	}
}

/**
 * save the 32bit integer t into the array uint8_t *t_bytes of length 4 
 * @param uint32_t t
 * @param uint8_t *t_Bytes
 */
void  int_To_Bytes(uint32_t t, uint8_t *t_Bytes){ 						 			
    int i;
	uint8_t *p=(uint8_t*) &t;                                                               
	for(i=0;i<4;i++){
		t_Bytes[i]= *(p+i);                                                                        
	}
	reverse(t_Bytes,4);                                                                         
}

/**
 * converts an array of bytes of max length 4 into an integer
 * @param int len
 * @param uint8_t *t_Bytes
 * @return int res
 */
uint32_t Bytes_To_Int(int len, uint8_t  *t_Bytes){								
	if(len > 4)
	{
		printf("error max length conversion = 4");
		return 1;
	}
	
	int res = 0;
	for (int i =0; i < len; i++)
	{
		res =  res*256 + t_Bytes[i];
	}
	return res;
}
