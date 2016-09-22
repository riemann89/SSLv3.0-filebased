#include "SSL_functions.h"
#include <openssl/md5.h>

/*****************************************FUNCTIONS***********************************************/

//CHANNEL FUNCTIONS

/*
 It allows the communication to the indicated talker: (0 - client, 1 - server, as defined in Talker enum)
 */

/**
 * Ciao ciao ciao
 * @param talker
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
    
    //VARIABLES DECLARATION
    FILE* token;
    Talker authorized_talker;																													//returning variable
    token = fopen("token.txt", "r");    																										//on token.txt is saved the current authorized talker 
    if(token == NULL) {
        perror("Failed to open token.txt - CheckCommunication() operation\n");							//is the file empty?? it shouldn't
        exit(1);
    }
	//SEEK WICH ONE IS AUTHORIZETD TO TALK//
    fscanf(token,"%u",&(authorized_talker));																						//read value from talker and insert it into the returning variable
    fclose(token);																																		//Close file
    if (authorized_talker!=client && authorized_talker!=server) {
        perror("Error in token.txt - nor client,nor server authorized\n");													//is the read value an acceptable value?? in case not return an error.
        exit(1);
    }
    return authorized_talker;
}

/*
 This function load a certificate from a file and return an array of bites where are contained certificate information in DER format
 */
Certificate* loadCertificate(char * cert_name){
    
    Certificate *certificate;
    certificate = calloc(1,sizeof(certificate));
    X509* certificate_x509 = NULL;
    uint8_t *buf;
    FILE* certificate_file;
    
    int len = 0;
    
    buf = NULL;
    certificate_file = fopen(cert_name, "r");
    
    if (certificate_file == NULL){
        perror("Certificate File not found\n");
        exit(1);
    }
    
    certificate_x509 = PEM_read_X509(certificate_file, NULL, 0, NULL);
    len = i2d_X509(certificate_x509, &buf);
    
    certificate->X509_der = buf;
    certificate->len = len;
    return certificate;
}

/*
 It writes each fields of the record_layer struct, pointed by the input, over SSLchannel.txt file.
 */
void sendPacketByte(RecordLayer *record_layer){
	
    //Variables Declarations//
    FILE* SSLchannel;
    uint8_t length16[4],*message,*length,*Mversion,*mversion;
    ContentType *type;
    int_To_Bytes(record_layer->length, length16);																		//int to bytes representation of the lenght
    //Channel Operations//
    SSLchannel=fopen("SSLchannelbyte.txt", "wb");															 		//channel opening in creating-writing mode
    if (SSLchannel == NULL) {
        perror("Failed to open SSLchannel.txt - sendPacket operation\n");										//error
        exit(1);
    }
    //extracting fields from record_layer, loading into temporary variables
    type=&record_layer->type;
    length=&length16[2];
    message=record_layer->message;
    Mversion=&record_layer->version.major;
    mversion=&record_layer->version.minor;
    //record_layer fields serializing phase equivalent to transmit  those on the channel, in this toy our channel is just a file named SSLChannelbyte.txt
    fwrite(type,sizeof(uint8_t),sizeof(uint8_t),SSLchannel);
    fwrite(Mversion,sizeof(uint8_t),1,SSLchannel);
    fwrite(mversion,sizeof(uint8_t),1,SSLchannel);
    fwrite(length,sizeof(uint8_t),2,SSLchannel);
    for (int i=0; i<(record_layer->length-5); i++) {
        fwrite((message+i),sizeof(uint8_t),1,SSLchannel);
    }
    //channel closure
    fclose(SSLchannel);
}

/* funzione per leggere il file*/

RecordLayer  *readchannel(){
    uint8_t *buffer;
    uint8_t record_header[5];//rivedere
    FILE* SSLchannel;
    uint16_t packet_size;
    RecordLayer *returning_record;
    ContentType type;
    ProtocolVersion version;
    
    SSLchannel = fopen("SSLchannelbyte.txt", "rb");
    if(SSLchannel==NULL)
    {
        printf("Error unable to read the SSLchannel\n");
        exit(1);
    }
    
    fread(record_header, sizeof(uint8_t), 5*sizeof(uint8_t), SSLchannel);
    packet_size = Bytes_To_Int(2, record_header + 3);
    
    //buffer = (uint8_t*)malloc((packet_size - 5)*sizeof(uint8_t)); //alloc enough memory to handle SSLchannel file
    buffer = (uint8_t*)calloc(packet_size - 5, sizeof(uint8_t));
    fseek(SSLchannel, SEEK_SET, 5);
    fread(buffer,sizeof(uint8_t),(packet_size-5)*sizeof(uint8_t), SSLchannel);// load file into buffer
    
    returning_record = calloc(6, sizeof(uint8_t));
    
    type = record_header[0];
    returning_record->type = type;	// assign type
    
    version.minor = record_header[1]; //loading version
    version.major = record_header[2];
    returning_record->version = version;// assign version
    returning_record->length = packet_size;// assign length to record
    returning_record->message= buffer;
    return returning_record;//assign pointer to message
}

/***************************************FREE FUNCTIONS**********************************************/

void FreeRecordLayer(RecordLayer *recordLayer){
    free(recordLayer->message);
    free(recordLayer);
}

void FreeHelloRequest(HelloRequest *hello_request){
    free(hello_request);
}

void FreeHandshake(Handshake *handshake){
    free(handshake->content);
    free(handshake);
}

void FreeClientServerHello(ClientServerHello *client_server_hello){
    free(client_server_hello->ciphersuite);
    free(client_server_hello->random);
    free(client_server_hello);
}

void FreeCertificate(Certificate *certificate){
    free(certificate->X509_der);
    free(certificate);
}

void FreeCertificateRequest(CertificateRequest *certificate_request){
    free(certificate_request->certificate_authorities);
    free(certificate_request);
}

void FreeServerDone(ServerDone *server_done){
    free(server_done);
}

void FreeCertificateVerify(CertificateVerify *certificate_verify){
    free(certificate_verify->signature);
    free(certificate_verify);
}

void FreeClientKeyExchange(ClientKeyExchange *client_key_exchange){
    free(client_key_exchange->parameters);
    free(client_key_exchange);
}

void FreeServerKeyExchange(ServerKeyExchange *server_key_exchange){
    free(server_key_exchange->parameters);
    free(server_key_exchange->signature);
    free(server_key_exchange);
}

void FreeCertificateFinished(Finished *finished){
    free(finished);
}

/********************FUNCTION TO CONSTRUCT HANDSHAKE PROTOCOL MESSAGE TYPES*************************/
/* Message types to Handshake */
Handshake *HelloRequestToHandshake(){
    //VARIABLE DECLARATION//
    Handshake *handshake;
    uint8_t* Bytes;
    
    //MEMORY ALLOCATION//
    Bytes = NULL;
    handshake=(Handshake*)calloc(1, sizeof(handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ServerDoneToHandshake operation");
        exit(1);
    }
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = HELLO_REQUEST;//handshake fields initialization
    handshake->length = 5;
    handshake->content = Bytes;
    return handshake;
}

Handshake *ClientServerHelloToHandshake(ClientServerHello *client_server_hello){
    //VARIABLE DECLARATION//
    CipherSuite *cipher;
    Handshake *handshake; 																		 	//returning variable
    uint8_t timeB[4]; 																					//current time bytes representation
    uint8_t session[4];			 																		//session bytes representation
    uint8_t cipher_codes[client_server_hello->length-38]; // 38= Random(32)+session(4) + version(1) + length(1)
    														//array of all ciphers supported
    uint8_t *Bytes;							//Used to serialize various fields of ClientServerHello and then pass to Handshake->content field
    
    //MEMORY ALLOCATION//
    Bytes =(uint8_t*)calloc(client_server_hello->length,sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    handshake=(Handshake*)calloc(1,sizeof(handshake));								//handshake memory allocation
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    cipher = client_server_hello->ciphersuite;   //temporary vector containing all cipher codes - it is requested to perform following memcopy
    for (int i=0;i<(client_server_hello->length-38);i++){  
        cipher_codes[i]=(cipher+i)->code;
    }
    int_To_Bytes(client_server_hello->random->gmt_unix_time, timeB);   	    //unix_time 
    int_To_Bytes(client_server_hello->sessionId, session);  								// session values to bytes transformation
    Bytes[0]=client_server_hello->version;   														//serializing client/server_hello field into bytes data vector
    memcpy(Bytes+1 ,session, 4);
    memcpy(Bytes+5 ,timeB , 4);
    memcpy(Bytes+9, client_server_hello->random->random_bytes,28);
    memcpy(Bytes+37, cipher_codes,client_server_hello->length-38);       		//38= version(1)+length(1)+session(4)+random(32)
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = client_server_hello->type;   												//handshake fields initialization
    handshake->length = client_server_hello->length + 3;
    handshake->content = Bytes;
    return handshake;
}

Handshake *CertificateToHandshake(Certificate *certificate){
    //VARIABLE DECLARATION//
    Handshake *handshake; 																		 	//returning variable
    //session bytes representation
    uint8_t *Bytes;																								//Used to serialize various fields of ClientServerHello and then pass to Handshake->content field
    //MEMORY ALLOCATION//
    Bytes =(uint8_t*)calloc(certificate->len, sizeof(uint8_t));																								 //bytes data vector, as said Bytes is an array which represents client_server_hello
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    handshake=(Handshake*)calloc(1, sizeof(handshake));								//handshake memory allocation
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    memcpy(Bytes, certificate->X509_der, certificate->len);       		//38= version(1)+length(1)+session(4)+random(32)
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = CERTIFICATE;   												//handshake fields initialization
    handshake->length = certificate->len + 4;
    handshake->content = Bytes;
    return handshake;
}

Handshake *ClientKeyExchangeToHandshake(ClientKeyExchange *client_key_exchange){
    Handshake *handshake;
    uint8_t *Bytes;
    uint32_t len_parameters;
    
    len_parameters = client_key_exchange->len_parameters;
    
    Bytes = (uint8_t*)calloc(client_key_exchange->len_parameters, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientKeyExchangeToHandshake operation");
        exit(1);
    }
    
    handshake=(Handshake*)calloc(1,sizeof(handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientKeyToHandshake operation");
        exit(1);
    }
    
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    memcpy(Bytes, client_key_exchange->parameters, len_parameters);
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = CLIENT_KEY_EXCHANGE;
    handshake->length = 4 + len_parameters;
    handshake->content = Bytes;
    
    return handshake;
}

Handshake *CertificateRequestToHandshake(CertificateRequest *certificate_request){
    //VARIABLE DECLARATION//
    Handshake *handshake;
    uint8_t *Bytes;
    int bytes_size;
    
    bytes_size = certificate_request->list_length * certificate_request->name_lenght + 1;
    
    //MEMORY ALLOCATION//
    Bytes =(uint8_t*)calloc(bytes_size, sizeof(uint8_t));
    
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    handshake=(Handshake*)calloc(1, sizeof(handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    Bytes[0] = certificate_request->certificate_type;
    memcpy(Bytes + 1, certificate_request->certificate_authorities, bytes_size);
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = CERTIFICATE_REQUEST;   											//handshake fields initialization
    handshake->length = 4 + bytes_size;
    handshake->content = Bytes;
    return handshake;
}

Handshake *ServerDoneToHandshake(){
    //VARIABLE DECLARATION//
    Handshake *handshake;
    uint8_t* Bytes;
    
    //MEMORY ALLOCATION//
    Bytes = NULL;
    handshake=(Handshake*)calloc(1, sizeof(handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ServerDoneToHandshake operation");
        exit(1);
    }
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = SERVER_DONE;//handshake fields initialization
    handshake->length = 4;
    handshake->content = Bytes;
    return handshake;
}

Handshake *CertificateVerifyToHandshake(CertificateVerify *certificate_verify){
    Handshake *handshake;
    uint8_t *Bytes;
    int bytes_size;
    
    switch (certificate_verify->algorithm_type) {
        case SHA1_:
            bytes_size = 20;
            break;
        case MD5_1:
            bytes_size = 16;
        default:
            break;
    }
    
    Bytes = (uint8_t*)calloc(bytes_size, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - FinishedToHandshake operation");
        exit(1);
    }
    handshake=(Handshake*)calloc(1,sizeof(handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - FinishedToHandshake operation");
        exit(1);
    }
    
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    Bytes[0] = certificate_verify->algorithm_type;
    memcpy(Bytes + 1, certificate_verify->signature, bytes_size);
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = CERTIFICATE_VERIFY;
    handshake->length = 4 + bytes_size + 1;
    handshake->content = Bytes;
    
    return handshake;
}

Handshake *FinishedToHandshake(Finished *finished){
    Handshake *handshake;
    uint8_t *Bytes;
    
    Bytes = (uint8_t*)calloc(36, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("ERROR FinishedToHandshake: Failed to create Bytes pointer");
        exit(1);
    }
    handshake=(Handshake*)calloc(1, sizeof(handshake));
    if (handshake == NULL) {
        perror("ERROR FinishedToHandshake: Failed to create Handshake pointer");
        exit(1);
    }
    
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    
    memcpy(Bytes, finished->hash, 36); //MD5 + SHA1
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = FINISHED;
    handshake->length = 4 + 36;
    handshake->content = Bytes;
    
    return handshake;
}

/********************FUNCTION TO CONSTRUCT PACKET FROM HANDSHAKE*************************/

HelloRequest *HandshakeToHelloRequest(Handshake *handshake){
    HelloRequest *hello_request;
    
    if (handshake->msg_type != HELLO_REQUEST){
            perror("ERROR HandshakeToHelloRequest: handshake does not contain an hello request message.");
            exit(1);
        }
    
    hello_request = (HelloRequest*)calloc(1, sizeof(HelloRequest));
  
    
    
    if (hello_request == NULL){
        perror("ERROR HandshakeToHelloRequest: memory allocation leak.");
        exit(1);
    }
    
    return hello_request;
    }

ClientServerHello *HandshakeToClientServerHello(Handshake *handshake){
    ClientServerHello *client_server_hello;
    CipherSuite *ciphers;
    Random *random;
    ciphers = (CipherSuite*)calloc(handshake->length-41,sizeof(CipherSuite));    
    client_server_hello = (ClientServerHello*)calloc(1, sizeof(ClientServerHello));
    random = (Random*)calloc(1,sizeof(Random));
    
    random->gmt_unix_time = Bytes_To_Int(4, handshake->content + 5);
    
    if (handshake->msg_type != CLIENT_HELLO && handshake->msg_type != SERVER_HELLO){
        printf("%d\n",handshake->msg_type);
        perror("HandshakeToClientServerHello: handshake does not contain a client_hello/server_hello message.\n");
        exit(1);
    }
    
    memcpy(random->random_bytes, handshake->content + 9,28);
    memcpy(ciphers, handshake->content + 37, (handshake->length-41));
        
    client_server_hello->length = handshake->length-4;
    client_server_hello->version = handshake->content[0];
    client_server_hello->sessionId = Bytes_To_Int(4, handshake->content + 1);
    client_server_hello->random = random;

    client_server_hello->ciphersuite = ciphers;

    return client_server_hello;
}//RIVEDERE da completare

Certificate *HandshakeToCertificate(Handshake *handshake){
    Certificate *certificate;
    uint8_t *buffer;
    int certificate_len;
    
    if (handshake->msg_type != CERTIFICATE){
        perror("ERROR HandshakeToCertificate: handshake does not contain a certificate message.");
        exit(1);
    }
    
    certificate_len = handshake->length - 4;
    
    certificate = (Certificate *)calloc(1, sizeof(Certificate));
    
    if (certificate == NULL){
        perror("ERROR HandshakeToHelloRequest: memory allocation leak.");
        exit(1);
    }
    
    buffer = (uint8_t *)calloc(certificate_len, sizeof(uint8_t));
    
    memcpy(buffer, handshake->content, certificate_len);
    
    certificate->len = certificate_len;
    certificate->X509_der = buffer;
    
    return certificate;
}

ServerDone *HandshakeToServerdone(Handshake *handshake){
    ServerDone *server_done;
    
    if (handshake->msg_type != SERVER_DONE){
        perror("ERROR HandshakeToServerDone: handshake does not contain a server done message.");
        exit(1);
    }
    
    server_done = (ServerDone*)calloc(1, sizeof(ServerDone));
    
    if (server_done == NULL){
        perror("ERROR HandshakeToServerDone: memory allocation leak.");
        exit(1);
    }
    
    return server_done;

};//TOCHECK

CertificateVerify *HandshakeToCertificateVerify(Handshake *handshake){
    CertificateVerify *certificate_verify;
    uint8_t *signature;
    int signature_len;
    
    if (handshake->msg_type != CERTIFICATE_VERIFY){
        perror("ERROR HandshakeToCertificateVerify: handshake does not contain a certificate verify message.");
        exit(1);
    }
    
    certificate_verify = (CertificateVerify *)calloc(1, sizeof(CertificateVerify));
    if (certificate_verify == NULL){
        perror("ERROR HandshakeToCertificateVerify: memory allocation leak.");
        exit(1);
    }
    
    signature_len = handshake->length - 4;
    signature = (uint8_t *)calloc(signature_len, sizeof(uint8_t));
    if (signature == NULL){
        perror("ERROR HandshakeToCertificateVerify: memory allocation leak.");
        exit(1);
    }
    
    switch (signature_len) {
        case 20:
            certificate_verify->algorithm_type = SHA1_;
            break;
            
        case 16:
            certificate_verify->algorithm_type = MD5_1;
            break;
        default:
            perror("ERROR HandshakeToCertificateVerify: signature size not valid.");
            exit(1);
            
    }
    
    memcpy(signature, handshake->content, signature_len);
    
    return certificate_verify;
    
}//TOCHECK

ClientKeyExchange *HandshakeToClientKeyExchange(Handshake *handshake, KeyExchangeAlgorithm algorithm_type, uint32_t len_parameters){
    
    ClientKeyExchange *client_key_exchange;
    uint8_t *buffer;
    
    if (handshake->msg_type != CLIENT_KEY_EXCHANGE){
        perror("ERROR HandshakeToClientKeyExchange: handshake does not contain a client key message.");
        exit(1);
    }
    
    client_key_exchange = (ClientKeyExchange *)calloc(1, sizeof(ClientKeyExchange));
    
    if (client_key_exchange == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    client_key_exchange->algorithm_type = algorithm_type;
    
    client_key_exchange->len_parameters = len_parameters;
    
    buffer = (uint8_t *)calloc(len_parameters, sizeof(uint8_t));
    
    if (buffer == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    memcpy(buffer, handshake->content ,len_parameters);
    client_key_exchange->parameters = buffer;
    
    return client_key_exchange;
}//TOCHECK
ServerKeyExchange *HandshakeToServerKeyExchange(Handshake *handshake, KeyExchangeAlgorithm algorithm_type, SignatureAlgorithm signature_type, uint32_t len_parameters, uint32_t len_signature){
    
    ServerKeyExchange *server_key_exchange;
    
    if (handshake->msg_type != CLIENT_KEY_EXCHANGE){
        perror("ERROR HandshakeToClientKeyExchange: handshake does not contain a client key message.");
        exit(1);
    }
    
    server_key_exchange = (ServerKeyExchange *)calloc(1, sizeof(ServerKeyExchange));
    if (server_key_exchange == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    server_key_exchange->algorithm_type = algorithm_type;
    server_key_exchange->signature_type = signature_type;
    
    server_key_exchange->len_parameters = len_parameters;
    server_key_exchange->len_signature = len_signature;
    
    server_key_exchange->parameters = (uint8_t *)calloc(len_parameters, sizeof(uint8_t));
    
    if (server_key_exchange->parameters == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    server_key_exchange->signature = (uint8_t *)calloc(len_signature, sizeof(uint8_t));
    
    if (server_key_exchange->signature == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    memcpy(handshake->content, server_key_exchange->parameters, len_parameters);
    
    memcpy(handshake->content + len_parameters, server_key_exchange->signature, len_signature);
    
    return server_key_exchange;
}//TOCHECK

Finished *HandshakeToFinished(Handshake *handshake){
    Finished *finished;
   
    if (handshake->msg_type != FINISHED){
        perror("ERROR HandshakeToFinished: handshake does not contain a finished message.");
        exit(1);
    }
    
    finished = (Finished *)calloc(1, sizeof(Finished));
    if (finished == NULL){
        perror("ERROR HandshakeToFinished: memory allocation leak.");
        exit(1);
    }
    
    memcpy(finished->hash, handshake->content, 36);
    
    return finished;


}//TOCHECK

CertificateRequest *HandshakeToCertificateRequest(Handshake *handshake){
 CertificateRequest *certificate_request;
 uint8_t *buffer;
 int buffer_len;
 
 if (handshake->msg_type != CERTIFICATE_REQUEST){
 perror("ERROR HandshakeToCertificateRequest: handshake does not contain a certificate request message.");
 exit(1);
 }
 
 buffer_len = handshake->length - 4;
 
 certificate_request = (CertificateRequest *)calloc(1, sizeof(CertificateRequest));
 if (certificate_request == NULL){
 perror("ERROR HandshakeToCertificateRequest: memory allocation leak.");
 exit(1);
 }
 
 buffer = (uint8_t *)calloc(buffer_len, sizeof(uint8_t));
 if (buffer == NULL){
 perror("ERROR HandshakeToCertificateRequest: memory allocation leak.");
 exit(1);
 }
 
 memcpy(buffer, handshake->content, buffer_len);
 
 //certificate->len = certificate_len;
 //certificate->X509_der = buffer;
 
 return certificate_request;
 } //TODO Rivedere: non riesco a rappresentare le liste, rivedere anche la struttura certificate_request.

/***************************************HANDSHAKE TO/FROM RECORDLAYER******************************************************/

/* Handshake to RecordLayer */
RecordLayer *HandshakeToRecordLayer(Handshake *handshake){
    //VARIABLE DECLARATION//
    uint8_t *Bytes;
    uint8_t length24[4];
    RecordLayer *recordlayer;  																										//returning variable
    int len;
    //MEMORY ALLOCATION//
    Bytes =(uint8_t*)calloc(handshake->length,sizeof(uint8_t)); 			    								//bytes data vector allocation
    if (Bytes == NULL) { 																													//contain the lenght of corresponding vector
        perror("Failed to create Bytes pointer - HandshakeToRecordLayer operation");
        exit(1);
    }
    recordlayer = (RecordLayer*)calloc(1,sizeof(RecordLayer));																									//record layer allocation memory i need 5 extra-bytes  
    if (recordlayer == NULL) {
        perror("Failed to create recordlayer pointer - HandshakeToRecordLayer operation");
        exit(1);
    }
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    int_To_Bytes(handshake->length ,length24); 			  				  												//int of 4 bytes to int of 3 bytes and reversed
    len=handshake->length;							
    Bytes[0]=handshake->msg_type;																									//serializing handshake and store it into Bytes
    memcpy(Bytes+1 ,length24+1,3);                										 											// length24 + 1 cause i need only the last 3 bytes
    memcpy(Bytes+ 4 ,handshake->content,len-4); 																			// +4 since 4=type(1)+length(3)		
	//RECORDLAYER CONSTRUCTION//
    recordlayer->type=HANDSHAKE;																									//recordlayer fields initialization
    recordlayer->version=std_version;
    recordlayer->length=handshake->length+5;
    recordlayer->message=Bytes;
    return recordlayer;
}

RecordLayer *change_cipher_Spec_Record(){
    
    RecordLayer *recordlayer;
    uint8_t *byte;
    byte =(uint8_t*)calloc(1,sizeof(uint8_t)); 
    recordlayer = (RecordLayer*)calloc(1, sizeof(RecordLayer));
    
    byte[0]=1;
    
    recordlayer->type= CHANGE_CIPHER_SPEC;
    recordlayer->version= std_version;
    recordlayer->length= 6;
    recordlayer->message = byte;
    
    return recordlayer;   
}

/* RecordLayer to Handshake */
Handshake *RecordToHandshake(RecordLayer *record){
    Handshake *result;
    uint8_t *buffer;
    
    result = calloc(1, sizeof(Handshake));
    buffer = (uint8_t*)malloc((record->length - 9)*sizeof(uint8_t));
    
    if(record->type != HANDSHAKE){
        printf("\n RecordToHandshake: Error record is not a handshake,  parse failed");
        exit(1);
        return NULL;
    }
    
    memcpy(buffer,  record->message + 4, record->length - 9);
    result->length = record->length - 5;
    result->msg_type = record->message[0];
    result->content = buffer;

    return result;
    
}

//in this toy we set the priorities of the server in the file "PriorityList.txt", so that we are able to choose the best cipher supported according to that file, on this pourpose chiphersuites  are saved in decrescent order of  priority

void setPriorities(uint8_t *number,CipherSuite *priority){   															

    FILE* PriorityList; 																														
    PriorityList = fopen("PriorityList.txt", "wb");   																																													 	
    fwrite(number,sizeof(uint8_t),1,PriorityList);
    for(int i = 0; i<*number; i++){   																									

        fwrite(&(priority +i)->code,sizeof(uint8_t),1,PriorityList);
    }
    fclose(PriorityList);                                                                                                                    
}

//this function read from PryorityList.txt and the input struct ClientServerHello, comparing chiphers Priority and avaiable and choosing the best fitting in a naive way
uint8_t chooseChipher(ClientServerHello *client_supported_list){
    FILE* PriorityList;
    uint8_t choosen;
    PriorityList = fopen("PriorityList.txt", "rb");  	 																		
    uint8_t *buffer;
    buffer = (uint8_t *)malloc((32)*sizeof(uint8_t));
    fread(buffer, 32, 1, PriorityList);
    //printf("%d\n",buffer[0]);
    for(int i=1; i<(int)(buffer[0])+1; i++){
        //printf("%d, %02X \n", i, buffer[i]);
        for(int j=0;j<client_supported_list->length -38 ;j++){ 
           //printf("    %d: %02X\n",j,client_supported_list->ciphersuite[j].code);
            if(buffer[i]==client_supported_list->ciphersuite[j].code){  
                choosen = buffer[i];
                return choosen; 																									
            }
            
        }
    }
    printf("\nError, uncompatibles chiphers");   		
    exit(1);
}

KeyExchangeAlgorithm getAlgorithm(CipherSuite cipher){
    if(cipher.code>0&& cipher.code<11)
        return RSA_;
    if(cipher.code>10&& cipher.code<28)
        return DIFFIE_HELLMAN;
    if(cipher.code>27&& cipher.code<31)
        return FORTEZZA;
    perror("Cipher null or not a valid ");
    exit(1);
}

/* about certificates*/
uint8_t *MasterSecretGen(uint8_t *pre_master_secret, ClientServerHello *client_hello, ClientServerHello *server_hello){
    uint8_t *md5_1, *md5_2, *md5_3, *sha_1, *sha_2, *sha_3;
    MD5_CTX md5;
    SHA_CTX sha;
    uint8_t *master_secret;
    
    md5_1 = calloc(16, sizeof(uint8_t));
    md5_2 = calloc(16, sizeof(uint8_t));
    md5_3 = calloc(16, sizeof(uint8_t));
    sha_1 = calloc(20, sizeof(uint8_t));
    sha_2 = calloc(20, sizeof(uint8_t));
    sha_3 = calloc(20, sizeof(uint8_t));
    
    SHA1_Init(&sha);
    SHA1_Update(&sha, "A", sizeof(uint8_t));
    SHA1_Update(&sha, pre_master_secret, 48*sizeof(uint8_t));
    SHA1_Update(&sha, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
    SHA1_Update(&sha, client_hello->random->random_bytes, 28*sizeof(uint8_t));
    SHA1_Update(&sha, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
    SHA1_Update(&sha, server_hello->random->random_bytes, 28*sizeof(uint8_t));
    SHA1_Final(sha_1, &sha);
    
    SHA1_Init(&sha);
    SHA1_Update(&sha, "BB", sizeof(uint8_t));
    SHA1_Update(&sha, pre_master_secret, 48*sizeof(uint8_t));
    SHA1_Update(&sha, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
    SHA1_Update(&sha, client_hello->random->random_bytes, 28*sizeof(uint8_t));
    SHA1_Update(&sha, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
    SHA1_Update(&sha, server_hello->random->random_bytes, 28*sizeof(uint8_t));
    SHA1_Final(sha_2, &sha);
    
    SHA1_Init(&sha);
    SHA1_Update(&sha, "CCC", sizeof(uint8_t));
    SHA1_Update(&sha, pre_master_secret, 48*sizeof(uint8_t));
    SHA1_Update(&sha, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
    SHA1_Update(&sha, client_hello->random->random_bytes, 28*sizeof(uint8_t));
    SHA1_Update(&sha, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
    SHA1_Update(&sha, server_hello->random->random_bytes, 28*sizeof(uint8_t));
    SHA1_Final(sha_3, &sha);
    
    MD5_Init(&md5);
    MD5_Update(&md5, pre_master_secret, 48*sizeof(uint8_t));
    MD5_Update(&md5, sha_1, 20*sizeof(uint8_t));
    MD5_Final(md5_1, &md5);

    MD5_Init(&md5);
    MD5_Update(&md5, pre_master_secret, 48*sizeof(uint8_t));
    MD5_Update(&md5, sha_2, 20*sizeof(uint8_t));
    MD5_Final(md5_2, &md5);
    
    MD5_Init(&md5);
    MD5_Update(&md5, pre_master_secret, 48*sizeof(uint8_t));
    MD5_Update(&md5, sha_3, 20*sizeof(uint8_t));
    MD5_Final(md5_3, &md5);
    
    master_secret = calloc(48, sizeof(uint8_t));
    memcpy(master_secret, md5_1, 16*sizeof(uint8_t));
    memcpy(master_secret + 16, md5_2, 16*sizeof(uint8_t));
    memcpy(master_secret + 32, md5_3, 16*sizeof(uint8_t));
    
    return master_secret;
};
int writeCertificate(X509* certificate){
    /* Per leggere il der
    X509 *res= NULL;
    d2i_X509(&res, &buf, *len);
     */
    FILE* file_cert;
    
    file_cert=fopen("cert_out.crt", "w+");
    return PEM_write_X509(file_cert, certificate);
}
int readCertificate(){return 0;} //TODO ricostruisco il file del certificato da cui leggo i parametri che mi servono.
EVP_PKEY* readCertificateParam (Certificate *certificate){
    X509 *cert_509;
    EVP_PKEY *pubkey;
    cert_509 = d2i_X509(NULL, &(certificate->X509_der), certificate->len);
    pubkey = X509_get_pubkey(cert_509);
    
    return pubkey;
}
uint8_t* encryptPreMaster(EVP_PKEY *pKey, KeyExchangeAlgorithm Alg, uint8_t* pre_master_secret){
    	int flag = 0;
    	RSA *rsa;
        uint8_t *pre_master_secret_encrypted;
    
        switch(Alg){
            case RSA_:
                rsa = EVP_PKEY_get1_RSA(pKey);
                pre_master_secret_encrypted = (uint8_t*)calloc(RSA_size(rsa), sizeof(uint8_t));
                flag = RSA_public_encrypt(48, pre_master_secret, pre_master_secret_encrypted, rsa, RSA_PKCS1_PADDING);//TODO: rivedere sto padding
                break;
            case DIFFIE_HELLMAN:
                printf("CIAO");
                break;
            case FORTEZZA:
                printf("CIAO");
                break;
            default:
                perror("EncryptPreMaster error: unknown keyexchange algorithm.");
                exit(1);
                break;
        }
        
        return pre_master_secret_encrypted;
}
uint8_t* decryptPreMaster(KeyExchangeAlgorithm alg, uint8_t *enc_pre_master_secret){
    uint8_t *pre_master_secret;
    FILE *certificate;
    RSA *rsa_private_key;
    
    rsa_private_key = NULL;
    certificate = NULL;
    pre_master_secret = (uint8_t*)calloc(48, sizeof(uint8_t));
    

    switch(alg){
        case RSA_:
            certificate = fopen("certificates/RSA_server.key","rb");
            if (certificate == NULL){
                printf("decryptPreMaster error: memory leak - null pointer .");
                exit(1);
            }
            rsa_private_key = PEM_read_RSAPrivateKey(certificate, &rsa_private_key, NULL, NULL);
            RSA_private_decrypt(128, enc_pre_master_secret, pre_master_secret, rsa_private_key, RSA_PKCS1_PADDING);
            break;
            
        case DIFFIE_HELLMAN:
            break;
        case FORTEZZA:
            
        default:
            perror("decryptPreMaster error: unknown key exchange algorithm.");
            exit(1);
            break;
    }
    return pre_master_secret;
}

uint8_t* DecEncryptFinished(uint8_t *finished, int finished_lenght, CiphertAlgorithm ciphet_alg, uint8_t *master_key, int state){
    uint8_t *enc_finished;
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new(); //TODO: remember to freeeee
    
    switch (ciphet_alg) {
            
            
            
        case CNULL:
            
            break;
        case DES:
            break;
        
        case DES40:
            break;
        
        case RC4_:
            enc_finished = calloc(finished_lenght*sizeof(uint8_t), sizeof(uint8_t));
            EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, master_key, NULL, state);
            EVP_CipherUpdate(ctx, enc_finished, &finished_lenght, finished, finished_lenght);
            EVP_CipherFinal(ctx, enc_finished, &finished_lenght);
            break;
            
        default:
            perror("encryptFinished error: unknown cipher algorithm.");
            exit(1);
            break;
    }
    return enc_finished;
    
}