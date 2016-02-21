#include "SSL_functions.h"

/*****************************************FUNCTIONS***********************************************/

//CHANNEL FUNCTIONS

//Allows the Client communication #T
void OpenCommunicationClient(){
    int	reading_flag=1;
    FILE* token;
    
    token=fopen("token.txt", "w");
    if(token == NULL) {
        perror("Errore in apertura del file");
        exit(1);
    }
    fprintf(token,"%d",reading_flag);
    fflush(token);
    fclose(token);
}

//Allows the Server communication #T
void OpenCommunicationServer(){
    int	reading_flag=0;
    FILE* token;
    
    token=fopen("token.txt", "w");
    if(token == NULL) {
        perror("Errore in apertura del file");
        exit(1);
    }
    
    fprintf(token,"%d",reading_flag);
    fflush(token);
    fclose(token);
    
}

/*Check if Server/Client can communicate. #T
 Input "0" indicates ClientChecker, "1" indicates ServerChecker
 return "1" if talker can communicate, "0" otherwise.
 */
int CheckCommunication(int talker){
    FILE* token;
    int reading_flag = 0;
    
    switch (talker){
        case 0:
            token=fopen("token.txt", "r");
            if(token == NULL) {
                perror("Errore in apertura del file");
                exit(1);
            }
            fscanf(token,"%d",&reading_flag);
            fclose(token);
            if (reading_flag == 1)
                return 1;
            break;
            
        case 1:
            token=fopen("token.txt", "r");
            if(token == NULL) {
                perror("Errore in apertura del file");
                exit(1);
            }
            fscanf(token,"%d",&reading_flag);
            fclose(token);
            if (reading_flag == 0)
                return 1;
    }
    return 0;
}

/*
 -sendPacket-
 sends a packet over the channel
 */
void sendPacket(RecordLayer record_layer){// PASSARE IL PUNTATORE
    FILE* SSLchannel;
    
    SSLchannel=fopen("SSLchannel.txt", "wb"); //opening file in creating-writing mode
    fprintf(SSLchannel,"%x\n",record_layer.type); //content type
    fprintf(SSLchannel,"%x\n",record_layer.version.major);
    fprintf(SSLchannel,"%x\n",record_layer.version.minor);
    fprintf(SSLchannel, "%x",record_layer.length);
    for (int i=0; i< record_layer.length; i++) {
        fprintf(SSLchannel, "%x ",record_layer.message[i]);
    }
    fclose(SSLchannel);
}


/*
 -ClientServerHelloToBytes-
 writes client/server_hello parameters as an array of bytes that follows this pattern:[length,version,session,time,random,ciphersuite]
*/

uint8_t  *ClientServerHelloToBytes(ClientServerHello c){  //remember  to free
    
    Cipher_Suite *cipher;
    uint8_t timeB[4];
    uint8_t session[4];
    uint8_t cipher_codes[c.length-38];      //array of all cipher code
    uint8_t *Bytes = malloc(sizeof(uint8_t)*c.length); //allocation for bytes data vector
    
    cipher=c.ciphersuite;
    for (int i=0;i<(c.length-38);i++){      //temporary vector containing all cipher codes
        cipher_codes[i]=(*(cipher+i)).code;
    }

    intToBytes(c.random.gmt_unix_time, timeB);//uint32 to byte[4] transformation
    intToBytes(c.sessionId, session);
    
    
    Bytes[0]=c.length;                      //loading the returning vector
    Bytes[1]=c.version;
    memcpy(Bytes+2 ,session, 4);
    memcpy(Bytes+6 ,timeB , 4);
    memcpy(Bytes+10,c.random.random_bytes,28);
    memcpy(Bytes+38, cipher_codes,c.length-38);
    
    return Bytes;
}














































