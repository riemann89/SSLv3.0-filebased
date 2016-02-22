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
 ToDo: rendere più leggibile il codice inizializzando una variabile clientserverhello
*/

uint8_t* ClientServerHelloToBytes(ClientServerHello* client_server_hello){  //remember  to free
    
    Cipher_Suite *cipher;
    uint8_t timeB[4];
    uint8_t session[4];
    uint8_t cipher_codes[(*client_server_hello).length-38];      //array of all cipher code
    uint8_t *Bytes;
    
    Bytes = malloc(sizeof(uint8_t)*(*client_server_hello).length); //allocation for bytes data vector
    
    cipher=(*client_server_hello).ciphersuite;
    for (int i=0;i<((*client_server_hello).length-38);i++){      //temporary vector containing all cipher codes
        cipher_codes[i]=(*(cipher+i)).code;
    }

    int_To_Bytes((*client_server_hello).random.gmt_unix_time, timeB);//uint32 to byte[4] transformation
    int_To_Bytes((*client_server_hello).sessionId, session);
    
    
    Bytes[0]=(*client_server_hello).length;                      //loading the returning vector
    Bytes[1]=(*client_server_hello).version;
    memcpy(Bytes+2 ,session, 4);
    memcpy(Bytes+6 ,timeB , 4);
    memcpy(Bytes+10,(*client_server_hello).random.random_bytes,28);
    memcpy(Bytes+38, cipher_codes,(*client_server_hello).length-38);
    
    return Bytes;
}

/*
 -HandshakeToBytes-
*/
//ToDo: To Be Tested
uint8_t *HandshakeToBytes(Handshake *handshake){
    uint8_t *Bytes;
    
    Bytes = malloc(sizeof(uint8_t)*(*handshake).content[0]+4); //since type (1 Byte), lenght (3 byte)

    Bytes[0]=(*handshake).msg_type;
    Bytes[1]=(*handshake).length.digits[0];
    Bytes[2]=(*handshake).length.digits[1];
    Bytes[3]=(*handshake).length.digits[2];
    memcpy(Bytes+4, (*handshake).content,(*handshake).content[0]+4);
    
    return Bytes;
}














































