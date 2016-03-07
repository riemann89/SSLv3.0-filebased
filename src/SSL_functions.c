#include "SSL_functions.h"

/*****************************************FUNCTIONS***********************************************/

//CHANNEL FUNCTIONS

/*
 It allows the communication to the indicated talker: (0 - client, 1 - server, as defined in Talker enum)
 */
void OpenCommunication(Talker talker){
    //VARIABLE DECLARATION//
    
    FILE* token;
    
    //CHECKING INPUT//
    
    if (talker!=client && talker!=server) {
        perror("Error in OpenCommunication -  Error in talker input (nor client, nor server input)");
        exit(1);
    }
    
    //AUTHORIZING SELECTED TALKER//
    
    token=fopen("token.txt", "w");
    if(token == NULL) {
        perror("Errore in apertura del file");
        exit(1);
    }
    fprintf(token,"%u",talker);
    fclose(token);
}

/*
 It checks who between server/client can communicate. It returns the authorized user that can communicate over the channel.
 */
Talker CheckCommunication(){
    //VARIABLES DECLARATION//
    
    FILE* token;
    Talker authorized_talker;
    
    token=fopen("token.txt", "r");
    if(token == NULL) {
        perror("Failed to open token.txt - CheckCommunication(client) operation");
        exit(1);
    }
    fscanf(token,"%u",&(authorized_talker));
    fclose(token);
    
    if (authorized_talker!=client && authorized_talker!=server) {
        perror("Error in token.txt - nor client,nor server authorized");
        exit(1);
    }
    
    return authorized_talker;
}


/*
 It writes each fields of the record_layer struct, pointed by the input, over SSLchannel.txt file.
 */
int sendPacket(RecordLayer *record_layer){
    
    //Variables Declarations//
    FILE* SSLchannel;
    uint8_t length16[4];
    int_To_Bytes(record_layer->length, length16);
    
    //Channel Operations//
    //channel opening in creating-writing mode
    SSLchannel=fopen("SSLchannel.txt", "wb");
    if (SSLchannel == NULL) {
        perror("Failed to open SSLchannel.txt - sendPacket operation");
        exit(1);
    }
    
    //record_layer fields writing phase
    fprintf(SSLchannel,"%02x\n",record_layer->type);
    fprintf(SSLchannel,"%02x\n",record_layer->version.major);
    fprintf(SSLchannel,"%02x\n",record_layer->version.minor);
    fprintf(SSLchannel, "%02x %02x\n",length16[2],length16[3]);
    for (int i=0; i<(record_layer->length-5); i++) {
        fprintf(SSLchannel, "%02x ",record_layer->message[i]);
    }
    
    //channel closure
    fclose(SSLchannel);
    return 1;
}

//funzione di prova per scrivere byte sul file


int sendPacketByte(RecordLayer *record_layer){
    
    //Variables Declarations//
    FILE* SSLchannel;
    uint8_t length16[4];
    int_To_Bytes(record_layer->length, length16);
    
	
    //Channel Operations//
    //channel opening in creating-writing mode
    SSLchannel=fopen("SSLchannelbyte.txt", "wb");
    if (SSLchannel == NULL) {
        perror("Failed to open SSLchannel.txt - sendPacket operation");
        exit(1);
    }
    
    //record_layer fields writing phase
	ContentType *type;
	type=&record_layer->type;
    uint8_t *length;
	length=&length16[2];
	

	uint8_t *mess;
	 mess=record_layer->message;
	 uint8_t *Mversion;
	 uint8_t *mversion;
	 Mversion=&record_layer->version.major;
	 mversion=&record_layer->version.minor;
	 
    fwrite(type,sizeof(uint8_t),sizeof(uint8_t),SSLchannel);
	
	
    fwrite(Mversion,sizeof(uint8_t),1,SSLchannel);
    fwrite(mversion,sizeof(uint8_t),1,SSLchannel);
    fwrite(length,sizeof(uint8_t),2,SSLchannel);

    for (int i=0; i<(record_layer->length-5); i++) {
        fwrite((mess+i),sizeof(uint8_t),1,SSLchannel);
    }
    
    //channel closure
    fclose(SSLchannel);
    return 1;
}


/* funzione per leggere il file*/

//Read Channel and return the reconstructed ClientHello from wich i will get the SeverHello wich i will have to send into the channel
ClientServerHello *readchannel(){                
	 

	
	uint8_t *buffer;
	FILE* SSLchannel;
	SSLchannel=fopen("SSLchannelbyte.txt", "r");
	
	ClientServerHello *returning_hello;
	returning_hello=(ClientServerHello*) calloc(1,sizeof(returning_hello));
	
	
	
	buffer = (uint8_t *)malloc((150)*sizeof(uint8_t));    // Enough memory for file + \0
    fread(buffer, 100, 1, SSLchannel);
	
	//returning_hello=(uint8_t*)calloc(100,sizeof(uint8_t));  non so bene come allocare dà errori
	uint8_t  version=(uint8_t)*(buffer+9);
	uint8_t  length= (uint8_t)*(buffer +8) -4 + 1;  //tolgo i byte in più del handshake  (version + length) e aggiungo il byte di lunghezza
	
	uint8_t session[4];
	for(int i =0;i<4;i++){
	session[i]= *(buffer + 10 + i);
	}
	reverse(session,4);   // trasformo i 4 byte in un intero da 4 byte

	uint32_t  SessionId=(uint32_t)(session[0] + session[1] *256 + session[2]*256*256 + session[3]*256*256);
	
	
	Random ran;
	
	ran.gmt_unix_time=time(0);  //metto il tempo nuovo in secondi.. dovrei trovare quella in millis
	for (int i =0; i<28;i++){
	ran.random_bytes[i]=(uint8_t)*(buffer + 18 +i);
	}
	
	//uint8_t  ciphers[length - 38]; //length of  ciphers
	Cipher_Suite *ciphers = malloc((50)*sizeof(Cipher_Suite));
	
	
	for (int i =0; i<length -38;i++){
	ciphers[i]= get_cipher_suite(buffer[18 +28 +i]);
	}
	//uint8_t *ciphers_ptr;
	
	//ciphers_ptr=&ciphers;
	

	
	returning_hello->version=version;
	returning_hello->length=length;
	returning_hello->sessionId=SessionId;
	returning_hello->random=ran;
	returning_hello->ciphersuite=ciphers;
	printf("%02x\n \n",ciphers[0].code);
    //returning_hello->ciphersuite= (Cipher_Suite*)ciphers_ptr;
	
	
	return returning_hello;
}


/*
 It encapsulates client/server_hello packet into an handshake packet. More precisely it takes as input the corresponding pointer to Client/Server_Hello packet and gives as output a pointer to an Handshake packet.
 
 REMEMBER TO free:
 -Bytes
 -handshake
 */

Handshake *ClientServerHelloToHandshake(ClientServerHello* client_server_hello){
    
    //VARIABLE DECLARATION//
    
    Cipher_Suite *cipher;
    Handshake *handshake;
    //current time bytes representation
    uint8_t timeB[4];
    //session bytes representation
    uint8_t session[4];
    //array of all cipher codes
    uint8_t cipher_codes[client_server_hello->length-38];//ToDo: rivedere il 38 (si può generalizzare)??
    //Bytes data vector pointer
    uint8_t *Bytes;
    
    //MEMORY ALLOCATION//
    
    //bytes data vector
    Bytes =(uint8_t*)calloc(client_server_hello->length,sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    //handshake
    handshake=(Handshake*)calloc(1,sizeof(handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    
    //temporary vector containing all cipher codes - it is requested to perform following memcopy
    cipher=client_server_hello->ciphersuite;
    for (int i=0;i<(client_server_hello->length-38);i++){
        cipher_codes[i]=(cipher+i)->code;
    }
    
    //unix_time and session values to bytes transformation
    int_To_Bytes(client_server_hello->random.gmt_unix_time, timeB);
    int_To_Bytes(client_server_hello->sessionId, session);
    
    //storing client/server_hello field into bytes data vector
    Bytes[0]=client_server_hello->length;
    Bytes[1]=client_server_hello->version;
    memcpy(Bytes+2 ,session, 4);
    memcpy(Bytes+6 ,timeB , 4);
    memcpy(Bytes+10,client_server_hello->random.random_bytes,28);
    memcpy(Bytes+38, cipher_codes,client_server_hello->length-38);
    
    //HANDSHAKE CONSTRUCTION//
    
    //handshake fields initialization
    handshake->msg_type = CLIENT_HELLO;
    handshake->length = client_server_hello->length + 4;
    handshake->content = Bytes;
    return handshake;
}

/*
 It encapsulates server_done packet into an handshake packet.
 REMEMBER TO free:
 -Bytes
 -handshake
 */
Handshake *ServerDoneToHandshake(){
    
    //VARIABLE DECLARATION//
    
    Handshake *handshake;
    uint8_t* Bytes;
    
    //MEMORY ALLOCATION//
    
    //bytes data vector
    Bytes=(uint8_t*)calloc(1,sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ServerDoneToHandshake operation");
        exit(1);
    }
    
    //handshake
    handshake=(Handshake*)calloc(1,sizeof(handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ServerDoneToHandshake operation");
        exit(1);
    }
    
    //HANDSHAKE CONSTRUCTION//
    
    //handshake fields initialization
    handshake->msg_type=SERVER_DONE;
    handshake->length=5;
    handshake->content=Bytes;
    
    return handshake;
}


/*
 It encapsulate an handshake packet into a record_layer packet.
 REMEMBER TO free:
 -Bytes
 -recordlayer
 */

RecordLayer *HandshakeToRecordLayer(Handshake *handshake){
    
    //VARIABLE DECLARATION//
    
    uint8_t *Bytes;
    uint8_t length24[4];
    RecordLayer *recordlayer;
    int len;
    
    //MEMORY ALLOCATION//
    
    //bytes data vector
    Bytes =(uint8_t*)calloc(handshake->content[0]+4,sizeof(uint8_t)); //since type (1 Byte), lenght (3 byte) and first element of content
    //contain the lenght of corresponding vector
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - HandshakeToRecordLayer operation");
        exit(1);
    }
    
    //record layer
    recordlayer = (RecordLayer*)calloc(handshake->length + 5,sizeof(RecordLayer));
    if (recordlayer == NULL) {
        perror("Failed to create recordlayer pointer - HandshakeToRecordLayer operation");
        exit(1);
    }
    
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    
    //int of 4 bytes to int of 3 bytes and reversed
    int_To_Bytes(handshake->length -1,length24); // -1 because I'm going to cancel the client length byte
    len=handshake->content[0]+4;//here the fact that content[0] contains highest layer lenght is exploited
    uint8_t temp[len];
    
    //storing handshake fields into bytes data vector
    Bytes[0]=handshake->msg_type;
    memcpy(Bytes+1,length24+1,3);
    memcpy(temp,handshake->content,len); // copio content in temp
    memcpy(Bytes+4, temp + 1,len-1); //metto temp in bytes saltando il byte di lunghezza che nel protocollo originale non c'è ma mi faceva comodo
    
    //RECORDLAYER CONSTRUCTION//
    
    //recordlayer fields initialization
    recordlayer->type=HANDSHAKE;
    recordlayer->version=std_version;
    recordlayer->length=handshake->length+5 - 1; // -1 because I've canceled the client length byte
    recordlayer->message=Bytes;
    
    return recordlayer;
}


// funzione per settare le priorità

 void setPriorities(uint8_t number,uint8_t *priority){   //numero ciphers supportati,  lista priorità da inserire in ordine decrescentenell'array priority[number]
	//creo il file
	FILE* PriorityList;
	PriorityList = fopen("PriorityList.txt", "wb");
   //carico le chiphers
     for(int i = 0; i<number; i++){
		 
		fwrite((priority +i),sizeof(uint8_t),1,PriorityList);
	    printf("%02x",*(priority+i));
	}
	
fclose(PriorityList);
}













































