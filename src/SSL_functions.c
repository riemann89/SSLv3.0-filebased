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
    uint8_t length16[4];
    int_To_Bytes(record_layer.length, length16);
    
    SSLchannel=fopen("SSLchannel.txt", "wb"); //opening file in creating-writing mode
    fprintf(SSLchannel,"%02x\n",record_layer.type); //content type
    fprintf(SSLchannel,"%02x\n",record_layer.version.major);
    fprintf(SSLchannel,"%02x\n",record_layer.version.minor);
    fprintf(SSLchannel, "%02x %02x\n",length16[2],length16[3]);
    for (int i=0; i<(record_layer.length-5); i++) {
        fprintf(SSLchannel, "%02x ",record_layer.message[i]);
    }
    fclose(SSLchannel);
}


/*
 -ClientServerHelloToBytes-
 writes client/server_hello parameters as an array of bytes that follows this pattern:[version,session,time,random,ciphersuite]
 ToDo: rendere più leggibile il codice inizializzando una variabile clientserverhello
*/
//remember  to free handshake.content



Handshake* ClientServerHelloToHandshake(ClientServerHello* client_server_hello){
    
    Cipher_Suite *cipher;
    Handshake *handshake;
    
    uint8_t timeB[4];
    uint8_t session[4];
    uint8_t cipher_codes[(*client_server_hello).length-38];      //array of all cipher code
    uint8_t *Bytes;
    
    Bytes = malloc(sizeof(uint8_t)*(*client_server_hello).length); //allocation for bytes data vector
    handshake=malloc(sizeof(uint8_t)*(client_server_hello->length+4));
    
    cipher=client_server_hello->ciphersuite;
    for (int i=0;i<((*client_server_hello).length-38);i++){      //temporary vector containing all cipher codes
        cipher_codes[i]=(*(cipher+i)).code;
    }

    int_To_Bytes((*client_server_hello).random.gmt_unix_time, timeB);//uint32 to byte[4] transformation
    int_To_Bytes((*client_server_hello).sessionId, session);
    
    
    Bytes[0]=(*client_server_hello).length;
    Bytes[1]=(*client_server_hello).version;
    memcpy(Bytes+2 ,session, 4);
    memcpy(Bytes+6 ,timeB , 4);
    memcpy(Bytes+10,client_server_hello->random.random_bytes,28);
    memcpy(Bytes+38, cipher_codes,(*client_server_hello).length-38);
    
    handshake->msg_type = CLIENT_HELLO;
    handshake->length = client_server_hello->length + 4;
    handshake->content = Bytes;

    
    return handshake;
}

/*
 -HandshakeToBytes-
*/
//ToDo: To Be Tested
RecordLayer *HandshakeToRecordLayer(Handshake *handshake){
    uint8_t *Bytes;
    uint8_t length24[4];
    RecordLayer *recordlayer;
    
    Bytes = malloc(sizeof(uint8_t)*(*handshake).content[0]+4); //since type (1 Byte), lenght (3 byte)
    recordlayer = malloc(sizeof(uint8_t)*(handshake->length + 5));

    int_To_Bytes(handshake->length,length24);
    
    Bytes[0]=(*handshake).msg_type;
    memcpy(Bytes+1,length24+1,3);
    memcpy(Bytes+4, (*handshake).content,(*handshake).content[0]+4);
    
    recordlayer->type=HANDSHAKE;
    recordlayer->version=std_version;
    recordlayer->length=handshake->length+5;
    recordlayer->message=Bytes;
    
    return recordlayer;
}














































