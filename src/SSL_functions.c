#include "SSL_functions.h"
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

/*****************************************FUNCTIONS***********************************************/

//CHANNEL FUNCTIONS
/**
 * Gives to talker the right to write on the main channel,
 * It writes an ID on the file token.txt (0 - client, 1 - server, as defined in Talker enum)
 * @param Talker talker
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

/**
 * It checks who between server/client can communicate. Return the rightful talker.
 * @return Talker authorized_talker
 */
Talker CheckCommunication(){
    
    //VARIABLES DECLARATION
    FILE* token;
    Talker authorized_talker;
    token = fopen("token.txt", "r");
    if(token == NULL) {
        perror("Failed to open token.txt - CheckCommunication() operation\n");
        exit(1);
    }
	//SEEK WICH ONE IS AUTHORIZETD TO TALK//
    fscanf(token,"%u",&(authorized_talker));
    fclose(token);
    if (authorized_talker!=client && authorized_talker!=server) {
        perror("Error in token.txt - nor client,nor server authorized\n");
        exit(1);
    }
    return authorized_talker;
}


/**
 * This function loads a certificate from a file and return an array of bites 
 * where are contained certificate information in DER format
 * @param char *cert_name
 * @return Certificate *certificate
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

/**
 * writes a record on SSLchannel.txt file
 * @param RecordLayer *record_layer
 */
void sendPacketByte(RecordLayer *record_layer){
	
    //Variables Declarations//
    FILE* SSLchannel;
    uint8_t length16[4],*message,*length,*Mversion,*mversion;
    ContentType *type;
    int_To_Bytes(record_layer->length, length16);
    
    //Channel Operations//
    SSLchannel=fopen("SSLchannelbyte.txt", "wb");															 		
    if (SSLchannel == NULL) {
        perror("Failed to open SSLchannel.txt - sendPacket operation\n");							
        exit(1);
    }
    //extracting fields from record_layer, loading into temporary variables//
    type=&record_layer->type;
    length=&length16[2];
    message=record_layer->message;
    Mversion=&record_layer->version.major;
    mversion=&record_layer->version.minor;
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


/**
 * Read the file SSLchannelbyte.txt and parse it into a record layer structure
 * @return RecordLayer *returning_record
 */
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
    
    buffer = (uint8_t*)calloc(packet_size - 5, sizeof(uint8_t));
    fseek(SSLchannel, SEEK_SET, 5);
    fread(buffer,sizeof(uint8_t),(packet_size-5)*sizeof(uint8_t), SSLchannel);// load file into buffer
    
    returning_record = calloc(6, sizeof(uint8_t));
    
    type = record_header[0];
    returning_record->type = type;
    
    version.major = record_header[1];
    version.minor = record_header[2];
    returning_record->version = version;
    returning_record->length = packet_size;
    returning_record->message= buffer;
    return returning_record;
}
/***************************************INIT FUNCTIONS**********************************************/
/**
 * init a ClientServerHello structure
 * @param HandshakeType type
 * @param uint32_t sessionId
 * @param uint8_t *ciphersuite_code
 * @param int ciphersuite_code_len
 * @return ClientServerHello *client_server_hello
 */
ClientServerHello *ClientServerHello_init(HandshakeType type, uint32_t sessionId, uint8_t *ciphersuite_code, int ciphersuite_code_len){
    ClientServerHello *client_server_hello;
    Random *random;
    
    if((client_server_hello = (ClientServerHello*)calloc(1, sizeof(ClientServerHello))) == 0){
        perror("ClientServerHello_init error: memory allocation leak.\n");
        exit(1);
    };
    
    if((random = (Random*)calloc(1, sizeof(Random))) == 0){
        perror("ClientServerHello_init error: memory allocation leak.\n");
        exit(1);
    };
	
    random->gmt_unix_time = (uint32_t)time(NULL);
    RAND_bytes(random->random_bytes, 28);
    
    client_server_hello->type = type;
    client_server_hello->version = 3;
    client_server_hello->random = random;
    client_server_hello->sessionId = sessionId;
    client_server_hello->ciphersuite_code = ciphersuite_code;
    client_server_hello->length = 38 + ciphersuite_code_len;
    
    return client_server_hello;
};

/**
 * init a ClientKeyExchange structure by Certificate message
 * @param Ciphersuite *ciphersuite
 * @param Certificate *certificate
 * @param ServerKeyExchange *server_key_exchange
 * @param uint8_t **premaster_secret
 * @param int *premaster_secret_size
 * @return ClientKeyExchange *client_key_exchange
 */
ClientKeyExchange *ClientKeyExchange_init(CipherSuite *ciphersuite, Certificate *certificate, ServerKeyExchange *server_key_exchange, uint8_t **premaster_secret, int *premaster_secret_size){
    
    ClientKeyExchange *client_key_exchange;
    uint8_t *premaster_secret_encrypted;
    int p_size, out_size;
    EVP_PKEY *pubkey;
    DH *dh = NULL;
    BIGNUM *pub_key_server;
    
    pubkey = readCertificateParam(certificate);
    p_size = (server_key_exchange->len_parameters - 1)/2;
    
    pub_key_server = BN_new();
    dh = DH_new();
    
    dh-> p = BN_bin2bn(server_key_exchange->parameters, p_size, NULL);
    dh-> g = BN_bin2bn(server_key_exchange->parameters + p_size, 1, NULL);
    if(DH_generate_key(dh) == 0){
        perror("DH keys generation error.");
        exit(1);
    }
    
    pub_key_server = BN_bin2bn(server_key_exchange->parameters + p_size + 1, p_size, NULL);

    if((client_key_exchange = (ClientKeyExchange*)calloc(1, sizeof(ClientKeyExchange))) == 0){
        perror("ClientKeyExchange_init error: memory allocation leak.\n");
        exit(1);
    };
     
    switch (ciphersuite->key_exchange_algorithm) {
        case RSA_:
            *premaster_secret_size = 48;
            *premaster_secret = (uint8_t*)calloc(*premaster_secret_size, sizeof(uint8_t));
            RAND_bytes(*premaster_secret, *premaster_secret_size);
            *premaster_secret[0] = std_version.major;
            *premaster_secret[1] = std_version.minor;
            premaster_secret_encrypted = AsymEnc(pubkey, *premaster_secret, 48, (size_t*)&out_size);
            
            client_key_exchange->parameters = premaster_secret_encrypted;
            client_key_exchange->len_parameters = out_size;
            break;
        case DH_:
            
            client_key_exchange->len_parameters = DH_size(dh);
            client_key_exchange->parameters = calloc(client_key_exchange->len_parameters, sizeof(uint8_t));
            BN_bn2bin(dh->pub_key, client_key_exchange->parameters);
            *premaster_secret = (uint8_t*)calloc(DH_size(dh), sizeof(uint8_t));
            *premaster_secret_size = DH_compute_key(*premaster_secret, pub_key_server, dh);
            break;
        default:
            break;
    }
    return client_key_exchange;
}

ServerKeyExchange *ServerKeyExchange_init(CipherSuite *ciphersuite, EVP_PKEY *private_key, ClientServerHello *client_hello, ClientServerHello *server_hello, DH **dh ){
    
    ServerKeyExchange *server_key_exchange;
    FILE *key_file;
    
    key_file=NULL;
    
    
       if((server_key_exchange = (ServerKeyExchange*)calloc(1, sizeof(ServerKeyExchange))) == 0){
        perror("ClientKeyExchange_init error: memory allocation leak.\n");
        exit(1);
    }
        //dh = DH_new();//TODO: remember to free
        *dh = get_dh2048();
    
        if(DH_generate_key(*dh) == 0){
            perror("DH keys generarion error.");
            exit(1);
        }
    
        server_key_exchange->len_parameters = BN_num_bytes((*dh)->p) + BN_num_bytes((*dh)->g) + BN_num_bytes((*dh)->pub_key);
     
        //TODO: questi mi sa che non vanno allocati
        server_key_exchange->parameters = (uint8_t*)calloc(server_key_exchange->len_parameters, sizeof(uint8_t));
          
        BN_bn2bin((*dh)->p, server_key_exchange->parameters);
        BN_bn2bin((*dh)->g, server_key_exchange->parameters + BN_num_bytes((*dh)->p));
        BN_bn2bin((*dh)->pub_key, server_key_exchange->parameters + BN_num_bytes((*dh)->p) + BN_num_bytes((*dh)->g));
    
    	//TODO rivedere l'inizializzazione delle variabili
        private_key = EVP_PKEY_new();    
        switch (ciphersuite->signature_algorithm) {
            case RSA_s:
                key_file = fopen("private_keys/RSA_server.key","rb");
                break;
            case DSA_s:
                key_file = fopen("private_keys/DSA_server.key","rb");
            default:
                perror("Error private key.");
                exit(1);
                break;
        }	
        private_key = PEM_read_PrivateKey(key_file, &private_key, NULL, NULL);
        printf("%d\n", EVP_PKEY_size(private_key));
        server_key_exchange->len_signature = EVP_PKEY_size(private_key);
        server_key_exchange->signature = (uint8_t*)calloc(server_key_exchange->len_signature,sizeof(uint8_t));
        server_key_exchange->signature = Signature_(ciphersuite, client_hello, server_hello, server_key_exchange->parameters, server_key_exchange->len_parameters, private_key);
        
        return server_key_exchange;
}

Certificate *Certificate_init(CipherSuite *ciphersuite){
    
    Certificate *certificate;
    
    switch (ciphersuite->key_exchange_algorithm){
        case RSA_:
            //strcpy((char*)&certificate_string, "certificates/RSA_server.crt");
            certificate = loadCertificate("certificates/RSA_server.crt");
            break;
        case DH_:
            switch (ciphersuite->signature_algorithm) {
                case RSA_s:
                    certificate = loadCertificate("certificates/RSA_server.crt");
                    break;
                case DSA_s:
                    certificate = loadCertificate("certificates/DSA_server.crt");
                    break;
                default:
                    break;
            }
            break;
        default:
            perror("Certificate error: type not supported.");
            exit(1);
            break;
        }
    return certificate;
}


/***************************************FREE FUNCTIONS**********************************************/
/**
 * free memory allocated by recordLayer
 * @param *recordLayer
 */
void FreeRecordLayer(RecordLayer *recordLayer){
    free(recordLayer->message);
    free(recordLayer);
}

/**
 * free memory allocated by hello_request
 * @param *hello_request
 */
void FreeHelloRequest(HelloRequest *hello_request){
    free(hello_request);
}

/**
 * free memory allocated by handshake
 * @param *handshake
 */
void FreeHandshake(Handshake *handshake){
    free(handshake->content);
    free(handshake);
}

/**
 * free memory allocated by client_server_hello
 * @param *client_server_hello
 */
void FreeClientServerHello(ClientServerHello *client_server_hello){
    free(client_server_hello->ciphersuite_code);//TODO Rivedere
    free(client_server_hello->random);
    free(client_server_hello);
}

/**
 * free memory allocated by certificate
 * @param *certificate
 */
void FreeCertificate(Certificate *certificate){
    free((uint8_t *)certificate->X509_der);
    free(certificate);
}

/**
 * free memory allocated by certificat_request
 * @param *certificate_request
 */
void FreeCertificateRequest(CertificateRequest *certificate_request){
    free(certificate_request->certificate_authorities);
    free(certificate_request);
}

/**
 * free memory allocated by server_done
 * @param *server_done
 */
void FreeServerDone(ServerDone *server_done){
    free(server_done);
}

/**
 * free memory allocated by certificate_verify
 * @param *certificate_verify
 */
void FreeCertificateVerify(CertificateVerify *certificate_verify){
    free(certificate_verify->signature);
    free(certificate_verify);
}

/**
 * free memory allocated by server_key_exchange
 * @param *client_key_exchange
 */
void FreeClientKeyExchange(ClientKeyExchange *client_server_key_exchange){
    free(client_server_key_exchange->parameters);
    free(client_server_key_exchange);
}

/**
 * free memory allocated by server_key_exchange
 * @param *server_key_exchange
 */
void FreeServerKeyExchange(ServerKeyExchange *client_server_key_exchange){
    free(client_server_key_exchange->parameters);
    free(client_server_key_exchange->signature);
    free(client_server_key_exchange);
}

/**
 * free memory allocated by finished
 * @param *finished
 */
void FreeFinished(Finished *finished){
    free(finished->hash);
    free(finished);  
}

/********************FUNCTION TO CONSTRUCT HANDSHAKE PROTOCOL MESSAGE TYPES*************************/
/* Message types to Handshake */

/**
 * creates a handshake wich contains a hellorequest
 * @return handshake
 */
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

/**
 * Serialize client_server_hello into handshake 
 * @param ClientServerHello *client_server_hello
 * @return Handshake *handshake
 */
Handshake *ClientServerHelloToHandshake(ClientServerHello *client_server_hello){
    //VARIABLE DECLARATION//
    uint8_t *cipher;
    Handshake *handshake;
    uint8_t timeB[4];
    uint8_t session[4];
    uint8_t cipher_codes[client_server_hello->length - 38];
    
    uint8_t *Bytes;
    
    //MEMORY ALLOCATION//
    Bytes =(uint8_t*)calloc(client_server_hello->length, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    handshake=(Handshake*)calloc(1,sizeof(handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    //CONTENT BYTES DATA VECTOR CONSTRUCTION//
    cipher = client_server_hello->ciphersuite_code;
    for (int i=0;i<(client_server_hello->length-38);i++){  
        cipher_codes[i]= *(cipher+i);
    }
    int_To_Bytes(client_server_hello->random->gmt_unix_time, timeB);
    int_To_Bytes(client_server_hello->sessionId, session);
    
    Bytes[0]=client_server_hello->version;
    
    memcpy(Bytes+1 ,session, 4);
    memcpy(Bytes+5 ,timeB , 4);
    memcpy(Bytes+9, client_server_hello->random->random_bytes,28);
    memcpy(Bytes+37, cipher_codes,client_server_hello->length-38);
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = client_server_hello->type;
    handshake->length = client_server_hello->length + 4;
    handshake->content = Bytes;
    return handshake;
}

/**
 * Serialize certificate into handshake
 * @param Certificate *certificate
 * @return Handshake *handshake
 */
Handshake *CertificateToHandshake(Certificate *certificate){
    //VARIABLE DECLARATION//
    Handshake *handshake;
    
    uint8_t *Bytes;
    
    //MEMORY ALLOCATION//
    Bytes =(uint8_t*)calloc(certificate->len, sizeof(uint8_t));
    
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
    memcpy(Bytes, certificate->X509_der, certificate->len);
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = CERTIFICATE;
    handshake->length = certificate->len + 4;
    handshake->content = Bytes;
    return handshake;
}

/**
 * Serialize client_key_exchange into handshake
 * @param ClientKeyExchange *client_key_exchange
 * @return Handshake *handshake
 */
Handshake *ClientKeyExchangeToHandshake(ClientKeyExchange *client_key_exchange){
    Handshake *handshake;
    uint8_t *Bytes;

    
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
    memcpy(Bytes, client_key_exchange->parameters, client_key_exchange->len_parameters);
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = CLIENT_KEY_EXCHANGE;
    handshake->length = 4 + client_key_exchange->len_parameters;
    handshake->content = Bytes;
    
    return handshake;
}


/**
 * Serialize server_key_exchange into handshake
 * @param ServerKeyExchange *server_key_exchange
 * @return Handshake *handshake
 */
Handshake *ServerKeyExchangeToHandshake(ServerKeyExchange *server_key_exchange){
    Handshake *handshake;
    uint8_t *Bytes;
      
    Bytes = (uint8_t*)calloc(server_key_exchange->len_parameters + server_key_exchange->len_signature, sizeof(uint8_t));
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
    memcpy(Bytes, server_key_exchange->parameters, server_key_exchange->len_parameters);
    memcpy(Bytes + server_key_exchange->len_parameters, server_key_exchange->signature, server_key_exchange->len_signature);
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = SERVER_KEY_EXCHANGE;
    handshake->length = 4 + server_key_exchange->len_parameters + server_key_exchange->len_signature;
    handshake->content = Bytes;
    
    return handshake;
}

/**
 * Serialize certificate_request into handshake
 * @param CertificateRequest *certificate_request
 * @return Handshake *handshake
 */
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

/**
 * Serialize certificate_verify into handshake
 * @param CertificateVerify *certificate_verify
 * @return Handshake *handshake
 */
Handshake *CertificateVerifyToHandshake(CertificateVerify *certificate_verify){
    Handshake *handshake;
    uint8_t *Bytes;
    int bytes_size;
    
    bytes_size = 0;
    Bytes = NULL;
    
    switch (certificate_verify->algorithm_type) {
        case SHA1_:
            bytes_size = 20;
            break;
        case MD5_1:
            bytes_size = 16;
            break;
        default:
            perror("CertificateVerifyToHandshake error: algorithm type not recognized.");
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

/**
 * Serialize finished into handshake
 * @param Finished *finished
 * @return Handshake *handshake
 */
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

/**
 * Parse handshake into hellorequest
 * @param Handshake *handshake
 * @return HelloRequest *hello_request
 */
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

/**
 *  Parse handshake into client_server_hello
 * @param Handshake handshake
 * @return ClientServerHello client_server_hello
 */
ClientServerHello *HandshakeToClientServerHello(Handshake *handshake){
    ClientServerHello *client_server_hello;
    uint8_t *ciphers;
    Random *random;
    
    ciphers = (uint8_t*)calloc(handshake->length-41, sizeof(uint8_t));
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
    
    client_server_hello->type = handshake->msg_type;
    client_server_hello->length = handshake->length - 4;
    client_server_hello->version = handshake->content[0];
    client_server_hello->sessionId = Bytes_To_Int(4, handshake->content + 1);
    client_server_hello->random = random;
    client_server_hello->ciphersuite_code = ciphers;

    return client_server_hello;
}//RIVEDERE da completare

/**
 *  Parse handshake into certificate
 * @param Handshake *handshake
 * @return Certificate *certificate
 */
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

/**
 *  Parse handshake into server_done
 * @param Handshake *handshake
 * @return ServerDone *server_done
 */
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

/**
 *  Parse handshake into certificate_verify
 * @param Handshake *handshake
 * @return CertificateVerify certificate_verify
 */
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

/**
 *  Parse handshake into server_key_exchange
 * @param Handshake *handshake
 * @param KeyExchangeAlgorithm algorithm_type
 * @param HashAlgorithm signature_type
 * @param uint32_t len_parameters
 * @param uint32_t len_signature
 * @return ServerKeyExchange *server_key_exchange
 */

ClientKeyExchange *HandshakeToClientKeyExchange(Handshake *handshake){
    
    ClientKeyExchange *client_server_key_exchange;
    
    if (handshake->msg_type != CLIENT_KEY_EXCHANGE){
        perror("ERROR HandshakeToClientKeyExchange: handshake does not contain a client key message.");
        exit(1);
    }
    
    client_server_key_exchange = (ClientKeyExchange *)calloc(1, sizeof(ClientKeyExchange));
    if (client_server_key_exchange == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    
    client_server_key_exchange->len_parameters = handshake->length - 4;
    
    client_server_key_exchange->parameters = (uint8_t *)calloc(client_server_key_exchange->len_parameters, sizeof(uint8_t));
    
    if (client_server_key_exchange->parameters == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    
    memcpy(client_server_key_exchange->parameters, handshake->content, client_server_key_exchange->len_parameters);
    
    return client_server_key_exchange;
}

ServerKeyExchange *HandshakeToServerKeyExchange(Handshake *handshake, Certificate *certificate){
    
    ServerKeyExchange *server_key_exchange;
    
    if (handshake->msg_type != SERVER_KEY_EXCHANGE){
        perror("ERROR HandshakeToClientKeyExchange: handshake does not contain a client key message.");
        exit(1);
    }
    
    server_key_exchange = (ServerKeyExchange *)calloc(1, sizeof(ServerKeyExchange));
    if (server_key_exchange == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    //EVP_PKEY *pkey = readCertificateParam(certificate);
    uint32_t len_signature = 128;
    
    server_key_exchange->len_signature = len_signature;
    server_key_exchange->len_parameters = handshake->length - 4 - len_signature;
    
    server_key_exchange->signature = (uint8_t *)calloc(len_signature, sizeof(uint8_t));
    server_key_exchange->parameters = (uint8_t *)calloc(server_key_exchange->len_parameters, sizeof(uint8_t));
    
    if (server_key_exchange->parameters == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    if (server_key_exchange->signature == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
    
    memcpy(server_key_exchange->parameters, handshake->content, server_key_exchange->len_parameters);
    memcpy(server_key_exchange->signature, handshake->content +  server_key_exchange->len_parameters , server_key_exchange->len_signature);
    
    return server_key_exchange;
}

/**
 *  Parse handshake into finished
 * @param Handshake *handshake
 * @return Finished *finished
 */
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
    
	finished->hash = (uint8_t*)calloc(36, sizeof(uint8_t));
    
    memcpy(finished->hash, handshake->content, 36);
    
    return finished;


}//TOCHECK

/**
 *  Parse handshake into certificate_request
 * @param Handshake *handshake
 * @return CertificateRequest *certificate_request
 */
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

/**
 * Serialize handshake into record_layer
 * @param Handshake *handshake
 * @return RecordLayer *recordlayer
 */
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
    int_To_Bytes(handshake->length ,length24); 			  				  												
    len=handshake->length;							
    Bytes[0] = handshake->msg_type;
    memcpy(Bytes+1 ,length24+1,3);
    memcpy(Bytes+ 4 ,handshake->content,len-4);
	//RECORDLAYER CONSTRUCTION//
    recordlayer->type=HANDSHAKE;
    recordlayer->version=std_version;
    recordlayer->length=handshake->length+5;
    recordlayer->message=Bytes;
    return recordlayer;
}

/**
 * creates a record containing a ChangeCipherSpech
 * @return RecordLayer *recordlayer 
 */
RecordLayer *ChangeCipherSpecRecord(){
    
    RecordLayer *recordlayer;
    uint8_t *byte;
    
    byte = (uint8_t*)calloc(1, sizeof(uint8_t)); 
    recordlayer = (RecordLayer*)calloc(1, sizeof(RecordLayer));    
    byte[0] = 1;
    
    recordlayer->type= CHANGE_CIPHER_SPEC;
    recordlayer->version= std_version;
    recordlayer->length= 6;
    recordlayer->message = byte;
    
    return recordlayer;   
}

/**
 * parse a record layer struct into an handshake struct
 * @param RecordLayer *record
 * @return Handshake *result
 */
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

/**
 * print in console the record layer pointed
 * @param RecordLayer *record_layer
 */
void printRecordLayer(RecordLayer *record_layer){
    uint8_t length_bytes[4];
    
    switch (record_layer->type) {
        case HANDSHAKE:
            switch (record_layer->message[0]) {
                case HELLO_REQUEST:
                    printf("HELLO REQUEST:\n");
                    break;
                case CLIENT_HELLO:
                    printf("CLIENT HELLO:\n");
                    break;
                case SERVER_HELLO:
                    printf("SERVER HELLO:\n");
                    break;
                case CERTIFICATE:
                    printf("CERTIFICATE:\n");
                    break;
                case SERVER_KEY_EXCHANGE:
                    printf("SERVER KEY EXCHANGE\n");
                    break;
                case CERTIFICATE_REQUEST:
                    printf("CERTIFICATE REQUEST\n");
                    break;
                case SERVER_DONE:
                    printf("SERVER DONE\n");
                    break;
            	case CERTIFICATE_VERIFY:
                    printf("CERTIFICATE VERITY\n");
                    break;
                case CLIENT_KEY_EXCHANGE:
                    printf("CLIENT KEY EXCHANGE\n");
                    break;
                case FINISHED:
                    printf("FINISHED\n");
                    break;
                default:
                    break;
            }
            break;
        case CHANGE_CIPHER_SPEC:
            printf("CHANGE CIPHER SPEC:\n");
        default:
            break;
    }
    int_To_Bytes(record_layer->length, length_bytes);
    
    printf("%02X ", record_layer->type);
    printf("%02X ", record_layer->version.major);
    printf("%02X ", record_layer->version.minor);
    printf("%02X ", length_bytes[2]);
    printf("%02X ", length_bytes[3]);
    
    for(int i=0; i<record_layer->length - 5; i++){
        printf("%02X ", record_layer->message[i]);
    }
    printf("\n\n");


}

/**
 * compare the client_supported_list of ciphersuite containded in ClientHello with the ones contained in the *filename,
 * which is the file whose content is the list of chipher supported by server.
 * Both list should be set in decrescent order of priority to choose the best possible one.  
 * @param ClientServerHello *client_supported_list
 * @param char *filename
 * @return uint8_t chosenChipher
 */
uint8_t chooseChipher(ClientServerHello *client_supported_list, char *filename){
    FILE* PriorityList;
    uint8_t choosen;   	 																		
    uint8_t *buffer;
    
    PriorityList = fopen(filename, "rb");  
    buffer = (uint8_t *)malloc((32)*sizeof(uint8_t));
    fread(buffer, 32, 1, PriorityList);
    
    for(int i=1; i< (buffer[0] +1); i++){
        for(int j=0;j<client_supported_list->length -38 ;j++){
            if(buffer[i] == client_supported_list->ciphersuite_code[j]){
                choosen = buffer[i];
                return choosen; 																									
            }
            
        }
    }
    perror("\nError, uncompatibles chiphers\n");
    exit(1);
}

/**
 * read from file a list of code of chiphersuites, the file should have a format 
 * first byte = number of the contained ciphersuite codes ,
 * following bytes = chiphersuite codes
 * @param char *filename
 * @param uint8_t *len
 * @return uint8_t *buffer 
 */
uint8_t *loadCipher(char* filename, uint8_t *len){
       
    FILE* CipherList;
    uint8_t *buffer;

    CipherList = fopen(filename, "rb");
    
   	if (CipherList == NULL){
        perror("loadCipher error: memory allocation leak.");
        exit(1);
    }
    
    fread(len, sizeof(uint8_t), 1, CipherList);
    buffer = (uint8_t *)malloc((len[0])*sizeof(uint8_t));
    fread(buffer, len[0]*sizeof(uint8_t), 1, CipherList);
    fclose(CipherList);
    
    return buffer;    
} 
/**
 * From the code of a ciphersuite decide if it match with RSA_, DIFFIE_HELLMAN or FORTEZZA.
 * @param uint8_t cipher_code
 * @return KeyExchangeAlgorithm 
 */
KeyExchangeAlgorithm getAlgorithm(uint8_t cipher_code){
    if(cipher_code> 0 && cipher_code < 11)
        return RSA_;
    if(cipher_code > 10 && cipher_code< 28)
        return DH_;
    if(cipher_code > 27 && cipher_code < 31)
        return KFORTEZZA;
    perror("Cipher null or not a valid \n");
    exit(1);
}

/*************************************** OTHERS ******************************************************/

/**
 * Initialize and return the ciphersuite corresponding to the ciphersuite_code 
 * @param uint8_t ciphersuite_code
 * @return CipherSuite *cipher_suite
 */
CipherSuite *CodeToCipherSuite(uint8_t ciphersuite_code){
    //INIZIALIZZARE CipherSuite
    
    CipherSuite *cipher_suite;
    
    cipher_suite = (CipherSuite*)calloc(1, sizeof(CipherSuite));
    
    switch (ciphersuite_code) {
        case 0x00:
            cipher_suite->key_exchange_algorithm = KNULL;
            cipher_suite->cipher_type = TNULL;
            cipher_suite->cipher_algorithm = CNULL;
            cipher_suite->iv_size = 0;
            cipher_suite->key_material = 0;
            cipher_suite->hash_algorithm = HNULL;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 0;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x01:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = TNULL;
            cipher_suite->cipher_algorithm = CNULL;
            cipher_suite->iv_size = 0;
            cipher_suite->key_material = 0;
            cipher_suite->hash_algorithm = MD5_1;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 16;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x02:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = TNULL;
            cipher_suite->cipher_algorithm = CNULL;
            cipher_suite->iv_size = 0;
            cipher_suite->key_material = 0;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x03:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = STREAM;
            cipher_suite->cipher_algorithm = RC4;
            cipher_suite->iv_size = 0;
            cipher_suite->key_material = 5;
            cipher_suite->hash_algorithm = MD5_1;
            cipher_suite->exportable = true;
            cipher_suite->hash_size = 16;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x04:
            cipher_suite->key_exchange_algorithm = RSA_;
        	cipher_suite->cipher_type = STREAM;
            cipher_suite->cipher_algorithm = RC4;
            cipher_suite->iv_size = 0;
            cipher_suite->key_material = 16;
            cipher_suite->hash_algorithm = MD5_1;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 16;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x05:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = STREAM;
            cipher_suite->cipher_algorithm = RC4;
            cipher_suite->iv_size = 0;
            cipher_suite->key_material = 16;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x06:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = RC2;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 5;
            cipher_suite->hash_algorithm = MD5_1;
            cipher_suite->exportable = true;
            cipher_suite->hash_size = 16;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x07:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = IDEA;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 16;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x08:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES40;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 5;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = true;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x09:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 8;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x0A:
            cipher_suite->key_exchange_algorithm = RSA_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES3;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 24;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = SNULL;
            break;
            
        case 0x0B:
            break;
            
        case 0x0C:
            break;
            
        case 0x0D:
            break;
        
        case 0x0E:
            break;
            
        case 0x0F:
            break;
            
        case 0x10:
            break;
            
        case 0x11:
            cipher_suite->key_exchange_algorithm = DH_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES40;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 5;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = true;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = DSA_s;
            break;
            
        case 0x12:
            cipher_suite->key_exchange_algorithm = DH_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 8;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = DSA_s;
            break;
            
        case 0x13:
            
            cipher_suite->key_exchange_algorithm = DH_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES3;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 24;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = DSA_s;
            break;
            
        case 0x14:
            
            cipher_suite->key_exchange_algorithm = DH_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES40;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 5;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = true;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = RSA_s;
            break;
            
        case 0x15:
            
            cipher_suite->key_exchange_algorithm = DH_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 8;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = RSA_s;
            break;
            
        case 0x16:
            
            cipher_suite->key_exchange_algorithm = DH_;
            cipher_suite->cipher_type = BLOCK;
            cipher_suite->cipher_algorithm = DES3;
            cipher_suite->iv_size = 8;
            cipher_suite->key_material = 24;
            cipher_suite->hash_algorithm = SHA1_;
            cipher_suite->exportable = false;
            cipher_suite->hash_size = 20;
            cipher_suite->signature_algorithm = RSA_s;
            break;
            
        case 0x17:
            break;
            
        case 0x18:
            break;
            
        case 0x19:
            break;
            
        case 0x1A:
            break;
            
        case 0x1B:
            break;
            
        case 0x1C:
            break;
            
        case 0x1D:
            break;
        
        case 0x1E:
            break;
            
        default:
            perror("CodeToCipherSuite Error: code not valid");
            exit(1);
            break;
    }
    return cipher_suite;
	}
CertificateType CodeToCertificateType(uint8_t ciphersuite_code){
    
    if (ciphersuite_code<= 0x0A && ciphersuite_code>=0x01){
        return RSA_SIGN;
    }
    else if (ciphersuite_code<= 0x0D && ciphersuite_code>=0x0B){
        return DSS_FIXED_DH;
    }
    else if (ciphersuite_code<= 0x10 && ciphersuite_code>=0x1E){
        return RSA_FIXED_DH;
    }
    else if (ciphersuite_code<= 0x13 && ciphersuite_code>=0x11){
        return DSS_EPHEMERAL_DH;
    }
    else if (ciphersuite_code<= 0x16 && ciphersuite_code>=0x14){
        return RSA_EPHEMERAL_DH;
    }
    else if (ciphersuite_code<= 0x1B && ciphersuite_code>=0x17){
        return DH_ANON;
    }
    else if (ciphersuite_code<= 0x1E && ciphersuite_code>=0x1C){
        return FORTEZZA_MISSI;
    }
    
    perror("CodeToCertificateType Error: ciphersuite_code not correct.");
    exit(1);
}

/**
 * BaseFunction that computes number_of_MD5 MD5 hash of the principal argument concatenated with random of Client and Server Hello //TODO
 * @param int numer_of_MD5
 * @param uint8_t *principal_argument
 * @param int principal_argument_size
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @return uint8_t *buffer
 */
uint8_t *BaseFunction(int numer_of_MD5, uint8_t* principal_argument, int principal_argument_size, ClientServerHello *client_hello, ClientServerHello *server_hello){
    
    uint8_t *buffer;
    uint8_t letter;
    MD5_CTX md5;
    SHA_CTX sha;
    uint8_t *md5_1, *sha_1;
    
    letter = 65;
    buffer = calloc(16*numer_of_MD5, sizeof(uint8_t));
    
    if (buffer == NULL){
        perror("ERROR base_function: memory allocation leak.");
        exit(1);
    }
    
    sha_1 = calloc(20, sizeof(uint8_t));
    
    if (sha_1 == NULL){
        perror("ERROR base_function: memory allocation leak.");
        exit(1);
    }
    
    md5_1 = calloc(16, sizeof(uint8_t));
    
    if (md5_1 == NULL){
        perror("ERROR base_function: memory allocation leak.");
        exit(1);
    }
    
    for(int i = 0; i < numer_of_MD5 ; i++){
        SHA1_Init(&sha);
        letter = letter + i;
        
        for (int j = 0; j < i + 1; j++) {
            SHA_Update(&sha, &letter, sizeof(uint8_t));
        }
        
        SHA1_Update(&sha, principal_argument, principal_argument_size*sizeof(uint8_t));
        SHA1_Update(&sha, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        SHA1_Update(&sha, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        SHA1_Update(&sha, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        SHA1_Update(&sha, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        
        SHA1_Final(sha_1, &sha);
        
        MD5_Init(&md5);
        MD5_Update(&md5, principal_argument, principal_argument_size*sizeof(uint8_t));
        MD5_Update(&md5, sha_1, 20*sizeof(uint8_t));
        MD5_Final(md5_1, &md5);
        
        memcpy(buffer + 16*i, md5_1, 16*sizeof(uint8_t));
    }
    return buffer;
    
}

/*************************************** CERTIFICATES ******************************************************/

/**
 * write certificate over a file named "cert_out-crt"
 * @param X509 *certificate
 * @return int exit_value  
 */
int writeCertificate(X509* certificate){
    /* Per leggere il der
    X509 *res= NULL;
    d2i_X509(&res, &buf, *len);
     */
    
    FILE* file_cert;
    
    file_cert=fopen("cert_out.crt", "w+");
    return PEM_write_X509(file_cert, certificate);
}

/**
 * extract the public key read from the certificate
 * @param Certificate *certificate
 * @return EVP_KEY *pubkey
 */
EVP_PKEY* readCertificateParam (Certificate *certificate){
    
    X509 *cert_509;
    EVP_PKEY *pubkey;
    const unsigned char *p;
    cert_509 = NULL;
    int len;
    
    p = certificate->X509_der;
    len = certificate->len;
    cert_509 = d2i_X509(NULL, &p, len);
    
    if(cert_509 == NULL){
        perror("readCertificateParam Error: memory allocation leak.");
        exit(1);
    }
    pubkey = X509_get_pubkey(cert_509);
    return pubkey;
}

/*************************************** KEYS GENERATION ******************************************************/
/**
 * derives the master_secret from pre_master_secret, client hello and server hello
 * @param uint8_t *pre_master_secret
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @return uint8_t *master_secret
 */
uint8_t *MasterSecretGen(uint8_t *pre_master_secret, int pre_master_len, ClientServerHello *client_hello, ClientServerHello *server_hello){
    uint8_t *master_secret;
    
    master_secret = BaseFunction(3, pre_master_secret, pre_master_len, client_hello, server_hello);
    
    if (master_secret == NULL) {
        perror("MasterSecretGen Error: memory allocation leak.");
        exit(1);
    }
    
    return master_secret;
}
/**
 * Generate key_block
 * @param uint8_t *master_secret
 * @param CipherSuite *cipher_suite
 * @param int *size
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @return uint8_t *key_block
 */
uint8_t *KeyBlockGen(uint8_t *master_secret, CipherSuite *cipher_suite, int *size, ClientServerHello *client_hello, ClientServerHello *server_hello){
    
    uint8_t *key_block, *final_client_write_key, *final_server_write_key, *client_write_iv, *server_write_iv;
    MD5_CTX md5;
    int key_block_size, key_block_size_temp;
    
    key_block = NULL;
    final_client_write_key = NULL;
    final_server_write_key = NULL;
    key_block_size = 0;
    key_block_size_temp = 0;
    
    if (cipher_suite->exportable == false) {
        key_block_size = 2*(cipher_suite->hash_size + cipher_suite->key_material + cipher_suite->iv_size);
        key_block_size = key_block_size + (16 - key_block_size % 16); //made a multiple of 16
        key_block = BaseFunction(key_block_size/16, master_secret, 48, client_hello, server_hello);
        *size = key_block_size;
    }
    else{
        //KeyBlock temp
        key_block_size_temp = 2*(cipher_suite->hash_size + cipher_suite->key_material);
        key_block_size_temp = key_block_size_temp + (16 -key_block_size_temp % 16); //made a multiple of 16
        key_block = BaseFunction(key_block_size_temp/16, master_secret, 48, client_hello, server_hello);
        
        //final write key
        //client
        final_client_write_key = calloc(16, sizeof(uint8_t));
        
    	MD5_Init(&md5);
        MD5_Update(&md5, key_block + 2*(cipher_suite->hash_size), cipher_suite->key_material);
        MD5_Update(&md5, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Update(&md5, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Final(final_client_write_key, &md5);
        
        //server
        final_server_write_key = calloc(16, sizeof(uint8_t));
        
        MD5_Init(&md5);
        MD5_Update(&md5, key_block + 2*(cipher_suite->hash_size) + cipher_suite->key_material, cipher_suite->key_material);
        MD5_Update(&md5, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Update(&md5, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Final(final_server_write_key, &md5);
        
        //iv bytes
        client_write_iv = calloc(16, sizeof(uint8_t));
        
        MD5_Init(&md5);
        MD5_Update(&md5, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Update(&md5, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Final(client_write_iv, &md5);
        
        //server
        server_write_iv = calloc(16, sizeof(uint8_t));
        
        MD5_Init(&md5);
        MD5_Update(&md5, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Update(&md5, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Final(server_write_iv, &md5);
        
        //construct final keyblock
        *size = 2*cipher_suite->hash_size + 64;
        key_block =(uint8_t*)realloc(key_block, (*size)*sizeof(uint8_t));
        memcpy(key_block + 2*(cipher_suite->hash_size), final_client_write_key, 16);
        memcpy(key_block + 2*(cipher_suite->hash_size) + 16, final_server_write_key, 16);
        memcpy(key_block + 2*(cipher_suite->hash_size) + 32, client_write_iv, 16);
        memcpy(key_block + 2*(cipher_suite->hash_size) + 48, server_write_iv, 16);
        
    }
    
    return key_block;
    
    
}

/**
 * Initialize a DH struct containing a prime p and a group generator g.
 * @return uint8_t *dh
 */

DH *get_dh2048(){
    static unsigned char dh2048_p[]={
        0xC5,0x36,0x72,0xCF,0x5A,0xA4,0x02,0xDA,0x0B,0xD2,0x49,0xE9,
        0x86,0x33,0xDF,0x51,0x06,0xE1,0x93,0x9E,0xDD,0x95,0xEA,0x5E,
        0x9A,0x80,0x47,0x3F,0x7D,0x4F,0x5D,0x19,0x09,0x9B,0xEA,0x6E,
        0x3B,0x89,0xD7,0xB8,0xC5,0xD5,0x28,0x57,0x4A,0xAA,0xEF,0x21,
        0x72,0x18,0x12,0x80,0xD5,0x15,0xEE,0x8C,0x9A,0x04,0xB0,0x23,
        0x89,0x98,0x62,0x5D,0xC8,0xA1,0x84,0x5E,0x1C,0x70,0x01,0xE1,
        0x1A,0x75,0x45,0xF0,0x90,0x7D,0x84,0x53,0x10,0xD5,0x65,0x98,
        0xF9,0x2E,0x7A,0xC4,0x5C,0xAF,0x76,0xB9,0x83,0xB3,0xF6,0x14,
        0x61,0x83,0xD8,0xCA,0x31,0x94,0xF4,0xF9,0x0B,0x6C,0x37,0x11,
        0x42,0xE7,0x16,0x50,0x76,0x24,0xE9,0x48,0x3E,0x19,0xFF,0x6E,
        0xEF,0x98,0x10,0x09,0x98,0x93,0x2E,0xAB,0x23,0xB5,0x9D,0xBB,
        0xB9,0x69,0xFD,0x6E,0xD1,0x85,0xA8,0xEF,0x8B,0x51,0xE7,0x0A,
        0x45,0x32,0x82,0x3B,0xD4,0x71,0x0C,0x8A,0x7A,0x79,0xF3,0x08,
        0x6C,0xBE,0xE3,0x61,0x11,0x40,0xF1,0x98,0x4E,0xF4,0x7B,0xD6,
        0xF5,0x6C,0xD5,0xCF,0x7B,0xF6,0xA2,0xBF,0xB8,0xAD,0xF2,0x29,
        0x3D,0x4E,0xDE,0x9A,0xEB,0xF5,0x8C,0x2E,0xEA,0x0D,0x0A,0x24,
        0xB3,0x82,0x84,0xEC,0x21,0xD2,0x87,0x8A,0xD2,0x12,0x12,0xA3,
        0x4F,0xC8,0xC0,0x09,0xDD,0x09,0x41,0xD2,0xEB,0x93,0xCE,0x94,
        0xBA,0xA2,0x5A,0x17,0x98,0x8A,0xB3,0x1C,0x13,0x6C,0xD8,0x7C,
        0x12,0x6E,0x57,0x0B,0x74,0xAC,0xF5,0xB6,0x22,0xBC,0xD4,0xC6,
        0x3C,0xC2,0x90,0x08,0xB8,0x9E,0x61,0x85,0xE8,0x3B,0x15,0x1B,
        0x2A,0x52,0x01,0xE3,
    };
    static unsigned char dh2048_g[]={
        0x02,
    };
    DH *dh;

    if ((dh=DH_new()) == NULL) return(NULL);
    dh->p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
    dh->g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL))
    { DH_free(dh); return(NULL); }
    return(dh);
}

/*************************************** ENCRYPTION ******************************************************/
//Asymmetric

/**
 * encrypts plaintext using public_key
 * @param EVP_KEY *pKey
 * @param uint8_t *plaintext
 * @param size_t inlen
 * @param size_t *outlen
 * @return uint8_t *ciphertext
 */
uint8_t* AsymEnc(EVP_PKEY *public_key, uint8_t* plaintext, size_t inlen, size_t *outlen){
   
    EVP_PKEY_CTX *ctx;
    uint8_t *ciphertext;
    //TODO: add controllo
    
    
    ctx = EVP_PKEY_CTX_new(public_key, NULL);
    
    if (!ctx){
        exit(1);}
    /* Error occurred */
    if (EVP_PKEY_encrypt_init(ctx) <= 0){
            exit(1);}
    /* Error */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){
            exit(1);}
    /* Error */
                
    /* Determine buffer length */
    if (EVP_PKEY_encrypt(ctx, NULL, outlen, plaintext, inlen) <= 0){
        exit(1);}
    /* Error */
                    
    ciphertext = OPENSSL_malloc(outlen);
    
    if (!ciphertext){
        exit(1);}
    /* malloc failure */
        
    if (EVP_PKEY_encrypt(ctx, ciphertext, outlen, plaintext, inlen) <= 0){
        exit(1);}
    /* Error */
    
    
    /* Encrypted data is outlen bytes written to buffer out */
    
    return ciphertext;
    /*
    EVP_PKEY_encrypt
    ciphertext = (uint8_t*)calloc(EVP_PKEY_size(public_key), sizeof(uint8_t));
    *out_size = RSA_public_encrypt(in_size, plaintext, ciphertext, rsa, RSA_PKCS1_PADDING);
    */
}

/**
 * decrypt ciphertext using private_key
 * @param KeyExchangeAlgorithm alg
 * @param uint8_t *ciphertext
 * @param size_t inlen
 * @param int *out_size
 * @return uint8_t *plaintext
 
 */
uint8_t* AsymDec(int private_key_type, uint8_t *ciphertext, size_t inlen, size_t *outlen, EVP_PKEY *private_key){

    uint8_t *plaintext;
    EVP_PKEY_CTX *ctx;
    
    
    /* NB: assumes key in, inlen are already set up
     * and that key is an RSA private key
     */
    
    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx){}

    if (EVP_PKEY_decrypt_init(ctx) <= 0){}
    
    switch (private_key_type) {//TODO: posso eliminare i due switch?
        case EVP_PKEY_RSA:
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){}
            break;
        case EVP_PKEY_DSA:
            //TODO: da gestire
            break;
        default:
            perror("");
            break;
    }
	
    if (EVP_PKEY_decrypt(ctx, NULL, outlen, plaintext, inlen) <= 0){}
                    
    plaintext = OPENSSL_malloc(outlen);
    
    if (!plaintext){}
        
    if (EVP_PKEY_decrypt(ctx, plaintext, outlen, ciphertext, inlen) <= 0){}
	//TODO: free e controlli
    return plaintext;

}//TODO

/**
 * decrypt an enciphred packet 
 * @param uint8_t *in_packet
 * @param int in_packet_len
 * @param int *out_packet_len
 * @param CipherSuite *cipher_suite
 * @param uint8_t *key_block
 * @param Talker key_talker
 * @param int state
 * @return uint8_t *out_packet
 */
uint8_t* DecEncryptPacket(uint8_t *in_packet, int in_packet_len, int *out_packet_len, CipherSuite *cipher_suite, uint8_t* key_block, Talker key_talker, int state){
    
    uint8_t *out_packet;
    EVP_CIPHER_CTX *ctx;
    uint8_t *key, *iv;
    uint8_t shift1, shift2;
    
    
    shift1 = 0;
    shift2 = 0;
    key = NULL;
    iv = NULL;
    out_packet = NULL;
    
    ctx = EVP_CIPHER_CTX_new();
    if (cipher_suite->exportable) {
        if (key_talker == server) {
            shift1 = 16;
            shift2 = 16;
        }
        key = key_block + (2*cipher_suite->hash_size + shift1);
        iv = key + (32 + shift2);
        
    }
    else{
        if (key_talker == server) {
            shift1 = cipher_suite->key_material;
            shift2 = cipher_suite->iv_size;
        }
        key = key_block + (2*cipher_suite->hash_size + shift1);
        iv = key + (2*cipher_suite->key_material + shift2);
    }

    switch (cipher_suite->cipher_algorithm) {
        case CNULL:
            //TODO da gestire
            break;
            
        case RC4:
            switch (cipher_suite->key_material) {
                case 5:
                    EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, key, iv, state);
                    EVP_CIPHER_CTX_set_key_length(ctx, 40);
                    break;
                case 16:
                    //beta
                    EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, key, iv, state);
                    break;
                    
                default:
                    perror("DecEncryptPacket error: RC4 size not corrected.\n");
                    exit(1);
                    break;
            }
            break;
            
        case RC2:
            EVP_CipherInit_ex(ctx, EVP_rc2_40_cbc(), NULL, key, iv, state);
            break;
        
        case IDEA:
            EVP_CipherInit_ex(ctx, EVP_idea_cbc(), NULL, key, iv, state);
            break;
        
        case DES40:
            EVP_CipherInit_ex(ctx, EVP_des_cbc(), NULL, key, iv, state);
            EVP_CIPHER_CTX_set_key_length(ctx, 40);
            break;
        
        case DES:
            EVP_CipherInit_ex(ctx, EVP_des_cbc(), NULL, key, iv, state);
            break;
        
        case DES3: //TODO da sistemare
            EVP_CipherInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv, state);

            break;
        
        default:
            perror("DecEncryptPacket error: unknown cipher algorithm.");
            exit(1);
            break;
    }
    int tmp_len;
    
    out_packet = calloc(1024, sizeof(uint8_t)); //TODO: ALLOCARE IL MAX
    
    EVP_CipherUpdate(ctx, out_packet, out_packet_len, in_packet, in_packet_len);
    EVP_CipherFinal_ex(ctx, out_packet + *out_packet_len, &tmp_len); //TODO non si capisce a che serve sta tmp_len
    *out_packet_len += tmp_len;
    EVP_CIPHER_CTX_free(ctx);
    
    return out_packet;
    
}

/**
 * MAC of the Handshake hand.
 * could be made using sha1 or md5 according to the CipherSuite cipher in input
 * @param CipherSuite cipher
 * @param Handshake *hand
 * @param uint8_t *macWriteSecret
 * @return uint8_t *sha_fin or *md5_fin
 */
uint8_t* MAC(CipherSuite *cipher, Handshake *hand, uint8_t* macWriteSecret){//TODO: passare il keyblock
    
    MD5_CTX md5,md52;
    SHA_CTX sha, sha2;
    uint64_t seq_num = 1;
    uint32_t len = hand->length - 4;
    
    
    if(cipher->signature_algorithm == SHA1_){
        
        uint8_t *sha_fin;
        sha_fin = calloc(20, sizeof(uint8_t));
        
        SHA1_Init(&sha);
        SHA1_Init(&sha2);
        SHA1_Update(&sha, macWriteSecret, 16*sizeof(uint8_t));
        SHA1_Update(&sha,pad_1, sizeof(pad_1));
        SHA1_Update(&sha, &seq_num, sizeof(uint64_t));
        SHA1_Update(&sha, &hand->msg_type , sizeof(uint8_t));
        SHA1_Update(&sha, &len, sizeof(uint32_t));
        SHA1_Update(&sha, hand->content, (hand->length - 4)*sizeof(uint8_t));
        SHA1_Final(sha_fin,&sha);
        
        SHA1_Update(&sha2,macWriteSecret, 16*sizeof(uint8_t));
        SHA1_Update(&sha2,pad_2, sizeof(pad_2));
        SHA1_Update(&sha2, sha_fin,20*sizeof(uint8_t));
        
        SHA1_Final(sha_fin,&sha2);
            
        return sha_fin;
        
    }
    else if(cipher->signature_algorithm == MD5_1){
        
        MD5_Init(&md5);
        MD5_Init(&md5);
        uint8_t *md5_fin;
        md5_fin = calloc(16, sizeof(uint8_t));
        
        
        MD5_Init(&md5);
        MD5_Init(&md52);
        MD5_Update(&md5, macWriteSecret, 16*sizeof(uint8_t));
        MD5_Update(&md5,pad_1, sizeof(pad_1));
        MD5_Update(&md5, &seq_num, sizeof(uint64_t));
        MD5_Update(&md5, &hand->msg_type ,sizeof(uint8_t));
        MD5_Update(&md5, &len, sizeof(uint32_t));
        MD5_Update(&md5,hand->content, (hand->length - 4)*sizeof(uint8_t));
        MD5_Final(md5_fin,&md5);
        
        MD5_Update(&md52,macWriteSecret, 16*sizeof(uint8_t));
        MD5_Update(&md52,pad_2, sizeof(pad_2));
        MD5_Update(&md52, md5_fin, 16*sizeof(uint8_t));
        
        MD5_Final(md5_fin, &md52);
            
        return md5_fin;
    }
    else{
        perror("MAC Error: signature algorithm not valid.");
        exit(1);
    }
}

/**
 * compute the SSL signature of params array of size len_params by private key pKey
 * @param CipherSuite *cipher
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @param uint8_t *params
 * @param int *len_params
 * @param EVP_PKEY *pKey
 * @return uint8_t *signature
 */
uint8_t* Signature_(CipherSuite *cipher, ClientServerHello *client_hello, ClientServerHello *server_hello, uint8_t* params, int len_params, EVP_PKEY *pKey){
    
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(mdctx);
    
    uint8_t *signature;
    uint8_t *data;
    unsigned int slen;
    signature = NULL;
    data = NULL;
    uint8_t temp[4];
    
    //hash
    data = (uint8_t*)calloc(62 + len_params, sizeof(uint8_t));
    signature = (uint8_t*)calloc(EVP_PKEY_size(pKey), sizeof(uint8_t));
    
    int_To_Bytes(client_hello->random->gmt_unix_time, temp);
    data[0] = temp[1];
    data[1] = temp[2];
    data[2] = temp[3];
    
    for (int i = 0; i<28; i++) {
        data[i+3] = client_hello->random->random_bytes[i];
    }
    
    int_To_Bytes(server_hello->random->gmt_unix_time, temp);
    data[31] = temp[1];
    data[32] = temp[2];
    data[33] = temp[3];
    
    for (int i = 0; i<28; i++) {
        data[i+34] = server_hello->random->random_bytes[i];
    }
    
    for (int i = 0; i<len_params; i++) {
        data[62 + i] = params[i];
    }
    

    switch (cipher->signature_algorithm){
        
        case RSA_s:
            EVP_SignInit_ex(mdctx, EVP_md5(), NULL);
            EVP_SignUpdate(mdctx, data, 62 + len_params);
            
            EVP_SignInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_SignUpdate(mdctx, data, 62 + len_params);
            break;
        
        case DSA_s:
            EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pKey);
            EVP_DigestSignUpdate(mdctx, data, 62 + len_params);
            
            break;
        
        default:
            perror("key exchange algorithm not supported");
            exit(1);
            break;
               
    }
    
    EVP_SignFinal(mdctx, signature, &slen, pKey);
    //TODO: freee
    
    return signature;
    
}

/**
 * verify the SSL signature of params array of size len_params by certificate
 * @param CipherSuite *cipher
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @param uint8_t *params
 * @param int *len_params
 * @param uin8_t *signature
 * @param int *len_signature
 * @param Certificate *certificate
 * @return uint8_t *signature
 */
void Verify_(CipherSuite *cipher, ClientServerHello *client_hello, ClientServerHello *server_hello, uint8_t* params, int len_params, uint8_t *signature, int len_signature, Certificate *certificate){
    
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(mdctx);
    
    uint8_t *data;
    data = NULL;
    uint8_t temp[4];
    
    EVP_PKEY *pubKey;
    
    pubKey = readCertificateParam(certificate);
    
    //hash
    data = (uint8_t*)calloc(62 + len_params, sizeof(uint8_t));
    
    int_To_Bytes(client_hello->random->gmt_unix_time, temp);
    data[0] = temp[1];
    data[1] = temp[2];
    data[2] = temp[3];
    
    for (int i = 0; i<28; i++) {
        data[i+3] = client_hello->random->random_bytes[i];
    }
    
    int_To_Bytes(server_hello->random->gmt_unix_time, temp);
    data[31] = temp[1];
    data[32] = temp[2];
    data[33] = temp[3];
    
    for (int i = 0; i<28; i++) {
        data[i+34] = server_hello->random->random_bytes[i];
    }
    
    for (int i = 0; i<len_params; i++) {
        data[62 + i] = params[i];
    }
    
    
    switch (cipher->signature_algorithm){
            
        case RSA_s:
            EVP_VerifyInit_ex(mdctx, EVP_md5(), NULL);
            EVP_VerifyUpdate(mdctx, data, 62 + len_params);
            
            EVP_VerifyInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_VerifyUpdate(mdctx, data, 62 + len_params);
            break;
            
        case DSA_s:
            EVP_VerifyInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_VerifyUpdate(mdctx, data, 62 + len_params);
            break;
            
        default:
            perror("key exchange algorithm not supported");
            exit(1);
            break;
            
    }
    
    if(EVP_VerifyFinal(mdctx, signature, len_signature, pubKey) == 1){
        printf("Signature correct.\n");
    }
    else{
        perror("Signature non corretta");
        exit(1);
    }
}















