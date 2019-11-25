#include "SSL_functions.h"
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

/***************************************INIT FUNCTIONS**********************************************/
/**
 * init a ClientServerHello structure
 * @param HandshakeType type
 * @param uint32_t sessionId
 * @param uint8_t *ciphersuite_code
 * @param int ciphersuite_code_len
 * @return ClientServerHello *client_server_hello
 */
ClientServerHello *ClientServerHello_init(HandshakeType type, uint32_t sessionId, uint8_t *ciphersuite_code, uint8_t ciphersuite_code_len){
    ClientServerHello *client_server_hello;
    Random *random;
    uint8_t *cipher;
    
    client_server_hello = NULL;
    random = NULL;
    cipher = NULL;
    
    if((client_server_hello = (ClientServerHello*)calloc(1, sizeof(ClientServerHello))) == 0){
        perror("ClientServerHello_init error: memory allocation leak.\n");
        exit(1);
    };
    
    if((random = (Random*)calloc(1, sizeof(Random))) == 0){
        perror("ClientServerHello_init error: memory allocation leak.\n");
        exit(1);
    };
	
    if((cipher = (uint8_t*)calloc(ciphersuite_code_len, sizeof(uint8_t))) == 0){
        perror("ClientServerHello_init error: memory allocation leak.\n");
        exit(1);
    };
    
    memcpy(cipher, ciphersuite_code, ciphersuite_code_len);
    
    random->gmt_unix_time = (uint32_t)time(NULL);
    RAND_bytes(random->random_bytes, 28);
    
    client_server_hello->type = type;
    client_server_hello->version = 3;
    client_server_hello->random = random;
    client_server_hello->sessionId = sessionId;
    client_server_hello->ciphersuite_code = cipher;
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
    DH *dh;
    BIGNUM *pub_key_server;
    
    client_key_exchange = NULL;
    premaster_secret_encrypted = NULL;
    pubkey = NULL;
    dh = NULL;
    pub_key_server = NULL;
    out_size = 0;
    
    pubkey = readCertificateParam(certificate);

    if((client_key_exchange = (ClientKeyExchange*)calloc(1, sizeof(ClientKeyExchange))) == 0){
        perror("ClientKeyExchange_init error: memory allocation leak.\n");
        exit(1);
    };
     
    switch (ciphersuite->key_exchange_algorithm) {
        case RSA_:
            *premaster_secret_size = 48;
            *premaster_secret = (uint8_t*)calloc(*premaster_secret_size, sizeof(uint8_t));
            RAND_bytes(*premaster_secret, *premaster_secret_size);
            *(*premaster_secret) = std_version.major;
            *(*premaster_secret + 1) = std_version.minor;
            premaster_secret_encrypted = AsymEnc(pubkey, *premaster_secret, 48, (size_t*)&out_size);
            
            client_key_exchange->parameters = premaster_secret_encrypted;
            client_key_exchange->len_parameters = out_size;
            break;
        case DH_:
            p_size = (server_key_exchange->len_parameters - 1)/2;
            
           
            dh = DH_new();
            
            dh-> p = BN_bin2bn(server_key_exchange->parameters, p_size, NULL);
            dh-> g = BN_bin2bn(server_key_exchange->parameters + p_size, 1, NULL);
            
            
      
           
            if(DH_generate_key(dh) == 0){
                perror("DH keys generation error.");
                exit(1);
            }
            
            pub_key_server = BN_bin2bn(server_key_exchange->parameters + p_size + 1, p_size, NULL);
            
            client_key_exchange->len_parameters = DH_size(dh);
            client_key_exchange->parameters = calloc(client_key_exchange->len_parameters, sizeof(uint8_t));
            BN_bn2bin(dh->pub_key, client_key_exchange->parameters);
            free(*premaster_secret);
            *premaster_secret = (uint8_t*)calloc(DH_size(dh), sizeof(uint8_t));
            *premaster_secret_size = DH_compute_key(*premaster_secret, pub_key_server, dh);
            BN_free(pub_key_server);
            DH_free(dh);
           
            
            break;
        default:
            break;
    }
    EVP_PKEY_free(pubkey);
    return client_key_exchange;
}

ServerKeyExchange *ServerKeyExchange_init(CipherSuite *ciphersuite, EVP_PKEY *private_key, ClientServerHello *client_hello, ClientServerHello *server_hello, DH **dh ){
    
    ServerKeyExchange *server_key_exchange;
    FILE *key_file;
    unsigned int slen;
    
    key_file = NULL;
    slen = 0;
    
    
    if((server_key_exchange = (ServerKeyExchange*)calloc(1, sizeof(ServerKeyExchange))) == 0){
        perror("ClientKeyExchange_init error: memory allocation leak.\n");
        exit(1);
    	}

    *dh = get_dh2048();
    
    if(DH_generate_key(*dh) == 0){
        perror("DH keys generation error.");
        exit(1);
    	}
    
    server_key_exchange->len_parameters = BN_num_bytes((*dh)->p) + BN_num_bytes((*dh)->g) + BN_num_bytes((*dh)->pub_key);
    server_key_exchange->parameters = (uint8_t*)calloc(server_key_exchange->len_parameters, sizeof(uint8_t));
    
    BN_bn2bin((*dh)->p, server_key_exchange->parameters);
    BN_bn2bin((*dh)->g, server_key_exchange->parameters + BN_num_bytes((*dh)->p));
    BN_bn2bin((*dh)->pub_key, server_key_exchange->parameters + BN_num_bytes((*dh)->p) + BN_num_bytes((*dh)->g));
    
   
    private_key = EVP_PKEY_new();
    switch (ciphersuite->signature_algorithm) {
        case RSA_s:
            key_file = fopen("private_keys/RSA_server.key","rb");
            break;
        case DSA_s:
            key_file = fopen("private_keys/DSA_server.key","rb");
            break;
        default:
            perror("Error private key.");
            exit(1);
            break;
        }
    
    private_key = PEM_read_PrivateKey(key_file, &private_key, NULL, NULL);
    
    server_key_exchange->signature = Signature_(ciphersuite, client_hello, server_hello, server_key_exchange->parameters, server_key_exchange->len_parameters, private_key, &slen);
    server_key_exchange->len_signature = slen;
    
    EVP_PKEY_free(private_key);
    
    return server_key_exchange;
}

Certificate *Certificate_init(CipherSuite *ciphersuite){
    
    Certificate *certificate;
    
    certificate = NULL;
    
    switch (ciphersuite->key_exchange_algorithm){
        case RSA_:
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
                    perror("Certificate error: signature algorithm type not supported.");
                    exit(1);
                    break;
            }
            break;
        default:
            perror("Certificate error: certificate type not supported.");
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
    free(client_server_hello->ciphersuite_code);
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
void FreeClientKeyExchange(ClientKeyExchange *client_key_exchange){
    if(client_key_exchange != NULL){
    	free(client_key_exchange->parameters);
        free(client_key_exchange);
    }
}

/**
 * free memory allocated by server_key_exchange
 * @param *server_key_exchange
 */
void FreeServerKeyExchange(ServerKeyExchange *server_key_exchange){
    if(server_key_exchange != NULL){
    	free(server_key_exchange->parameters);
    	free(server_key_exchange->signature);
        free(server_key_exchange);
    }
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
    handshake=(Handshake*)calloc(1, sizeof(Handshake));
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

    Handshake *handshake;
    uint8_t timeB[4];
    uint8_t session[4];
    uint8_t *Bytes;
    
    handshake = NULL;
    Bytes = NULL;
	
    Bytes =(uint8_t*)calloc(client_server_hello->length, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    
    handshake=(Handshake*)calloc(1,sizeof(Handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }

    
    if (client_server_hello->length <= 38) {
        perror("clien_server_hello lenght error.");
        exit(1);
    }
    
    int_To_Bytes(client_server_hello->random->gmt_unix_time, timeB);
    int_To_Bytes(client_server_hello->sessionId, session);
    
    Bytes[0] = client_server_hello->version;
    
    memcpy(Bytes + 1 ,session, 4);
    memcpy(Bytes + 5 ,timeB , 4);
    memcpy(Bytes + 9, client_server_hello->random->random_bytes, 28);
    memcpy(Bytes + 37, client_server_hello->ciphersuite_code, client_server_hello->length - 38);
    
    //HANDSHAKE CONSTRUCTION//
    handshake->msg_type = client_server_hello->type;
    handshake->length = client_server_hello->length + 3;
    handshake->content = Bytes;
    
    return handshake;
}

/**
 * Serialize certificate into handshake
 * @param Certificate *certificate
 * @return Handshake *handshake
 */
Handshake *CertificateToHandshake(Certificate *certificate){
    Handshake *handshake;
    uint8_t *Bytes;
    
    handshake = NULL;
    Bytes = NULL;
    
    Bytes =(uint8_t*)calloc(certificate->len, sizeof(uint8_t));
    
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    
    handshake=(Handshake*)calloc(1, sizeof(Handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientServerHelloToHandshake operation");
        exit(1);
    }
    
    memcpy(Bytes, certificate->X509_der, certificate->len);
    
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
	
    handshake = NULL;
    Bytes = NULL;
    
    Bytes = (uint8_t*)calloc(client_key_exchange->len_parameters, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientKeyExchangeToHandshake operation");
        exit(1);
    }
    
    handshake=(Handshake*)calloc(1,sizeof(Handshake));
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
    
    handshake = NULL;
    Bytes = NULL;
      
    Bytes = (uint8_t*)calloc(server_key_exchange->len_parameters + server_key_exchange->len_signature, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - ClientKeyExchangeToHandshake operation");
        exit(1);
    }
    
    handshake=(Handshake*)calloc(1,sizeof(Handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ClientKeyToHandshake operation");
        exit(1);
    }
    
    //copying parameters into bytes
    memcpy(Bytes, server_key_exchange->parameters, server_key_exchange->len_parameters);
    memcpy(Bytes + server_key_exchange->len_parameters, server_key_exchange->signature, server_key_exchange->len_signature);
    
    //hanshake construction
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
    handshake=(Handshake*)calloc(1, sizeof(Handshake));
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


/**
 * generate an handshake containing a server done message
 * @return Handshake *handshake
 */
Handshake *ServerDoneToHandshake(){

    Handshake *handshake;
    uint8_t* Bytes;
    
    handshake = NULL;
    Bytes = NULL;
    
    handshake=(Handshake*)calloc(1, sizeof(Handshake));
    if (handshake == NULL) {
        perror("Failed to create handshake pointer - ServerDoneToHandshake operation");
        exit(1);
    }
    
    //hanshake construction
    handshake->msg_type = SERVER_DONE;
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
            exit(1);
            break;
    }
    
    Bytes = (uint8_t*)calloc(bytes_size, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("Failed to create Bytes pointer - FinishedToHandshake operation");
        exit(1);
    }
    handshake=(Handshake*)calloc(1,sizeof(Handshake));
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
    
    handshake = NULL;
    Bytes = NULL;
    
    Bytes = (uint8_t*)calloc(36, sizeof(uint8_t));
    if (Bytes == NULL) {
        perror("ERROR FinishedToHandshake: Failed to create Bytes pointer");
        exit(1);
    }
    
    handshake=(Handshake*)calloc(1, sizeof(Handshake));
    if (handshake == NULL) {
        perror("ERROR FinishedToHandshake: Failed to create Handshake pointer");
        exit(1);
    }
    
    //copying data into bytes
    
    memcpy(Bytes, finished->hash, 36); //size(MD5) + size(SHA1) == 36
    
    //hanshake construction
    handshake->msg_type = FINISHED;
    handshake->length = 40;
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
    
    client_server_hello = NULL;
    ciphers = NULL;
    random = NULL;   
    
    ciphers = (uint8_t*)calloc(handshake->length - 41, sizeof(uint8_t));
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
}

/**
 *  Parse handshake into certificate
 * @param Handshake *handshake
 * @return Certificate *certificate
 */
Certificate *HandshakeToCertificate(Handshake *handshake){
    Certificate *certificate;
    uint8_t *buffer;
    int certificate_len;
    
    certificate=NULL;
    buffer=NULL;
    certificate_len=0;
    
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
    
    server_done=NULL;
    
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
    
    certificate_verify=NULL;
    signature=NULL;
    signature_len=0;
    
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
 *  Parse handshake into client_key_exchange
 * @param Handshake *handshake
 * @return ServerKeyExchange *server_key_exchange
 */

ClientKeyExchange *HandshakeToClientKeyExchange(Handshake *handshake){
    
    ClientKeyExchange *client_server_key_exchange;
    
    client_server_key_exchange=NULL;
    
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

/**
 *  Parse handshake into server_key_exchange
 * @param Handshake *handshake
 * @param Certificate *certificate
 * @return ServerKeyExchange
 */
ServerKeyExchange *HandshakeToServerKeyExchange(Handshake *handshake, Certificate *certificate){
    
    ServerKeyExchange *server_key_exchange;
    
    server_key_exchange=NULL;
    
    if (handshake->msg_type != SERVER_KEY_EXCHANGE){
        perror("ERROR HandshakeToClientKeyExchange: handshake does not contain a client key message.");
        exit(1);
    }
    
    server_key_exchange = (ServerKeyExchange *)calloc(1, sizeof(ServerKeyExchange));
    if (server_key_exchange == NULL){
        perror("ERROR HandshakeToClientKeyExchange: memory allocation leak.");
        exit(1);
    }
	
    server_key_exchange->len_parameters = 513;
    server_key_exchange->len_signature = handshake->length - 4 - server_key_exchange->len_parameters;

    
    server_key_exchange->signature = (uint8_t *)calloc(server_key_exchange->len_signature, sizeof(uint8_t));
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
    
    finished=NULL;
   
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
}

/**
 *  Parse handshake into certificate_request
 * @param Handshake *handshake
 * @return CertificateRequest *certificate_request
 */
CertificateRequest *HandshakeToCertificateRequest(Handshake *handshake){
 
 CertificateRequest *certificate_request;
 uint8_t *buffer;
 int buffer_len;
 
 certificate_request=NULL;
 buffer=NULL;
 buffer_len=0;
 
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
 free(buffer);
 
 return certificate_request;
}

/***************************************HANDSHAKE TO/FROM RECORDLAYER******************************************************/

/**
 * Serialize handshake into record_layer
 * @param Handshake *handshake
 * @return RecordLayer *recordlayer
 */
RecordLayer *HandshakeToRecordLayer(Handshake *handshake){
    //VARIABLE DECLARATION//
    uint8_t *Bytes;
    uint8_t length24[4] = {0};
    RecordLayer *recordlayer;  																										//returning variable
    int len;
    
    Bytes=NULL;
    recordlayer=NULL;
    len=0;
    
    //MEMORY ALLOCATION//
    Bytes =(uint8_t*)calloc(handshake->length+5,sizeof(uint8_t)); //bytes data vector allocation
  
    if (Bytes == NULL) {      //contain the lenght of corresponding vector
        perror("Failed to create Bytes pointer - HandshakeToRecordLayer operation");
        exit(1);
    }
    recordlayer = (RecordLayer*)calloc(1,sizeof(RecordLayer));																									//record layer allocation memory i need 5 extra-bytes  
    if (recordlayer == NULL) {
        perror("Failed to create recordlayer pointer - HandshakeToRecordLayer operation");
        exit(1);
    }
      recordlayer->message=(uint8_t*)calloc(handshake->length+5,sizeof(uint8_t));
    
    
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
    memcpy(recordlayer->message,Bytes,handshake->length);
    
    //recordlayer->message=Bytes;
    free(Bytes);
    
    return recordlayer;
}

/**
 * creates a record containing a ChangeCipherSpech
 * @return RecordLayer *recordlayer 
 */
RecordLayer *ChangeCipherSpecRecord(){
    
    RecordLayer *recordlayer;
    uint8_t *byte;
    
    recordlayer=NULL;
    byte=NULL;
    
    //MEMORY ALLOCATION
    byte = (uint8_t*)calloc(1, sizeof(uint8_t)); 
    recordlayer = (RecordLayer*)calloc(1, sizeof(RecordLayer));    
    byte[0] = 1;
    
    //RECORDLAYER CONSTRUCTION
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
    
    result=NULL;
    buffer=NULL;
    
    //MEMORY ALLOCATION
    result = calloc(1, sizeof(Handshake));
    buffer = (uint8_t*)malloc((record->length - 9)*sizeof(uint8_t));
    
    if(record->type != HANDSHAKE){
        printf("\n RecordToHandshake: Error record is not a handshake,  parse failed");
        exit(1);
        return NULL;
    }
    
    //HANDSHAKE CONSTRUCTION
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
uint8_t chooseChipher(ClientServerHello *client_hello, char *filename){

    FILE* PriorityList;
    uint8_t choosen;   	 																		
    uint8_t *buffer;
    uint8_t number_of_ciphersuites;
    
    PriorityList=NULL;
    buffer=NULL;
    choosen =0;
    
    //reading ciphersuites
    PriorityList = fopen(filename, "rb");
    fread(&number_of_ciphersuites, sizeof(uint8_t), sizeof(uint8_t), PriorityList);
    buffer = (uint8_t *)malloc((number_of_ciphersuites)*sizeof(uint8_t));
    fread(buffer, number_of_ciphersuites, sizeof(uint8_t), PriorityList);
    
    printf("\n choose cipher\n");
    printf("\n client %02X ",client_hello->ciphersuite_code[0]);
    printf("\n\n");
    
    for(int i = 0; i< number_of_ciphersuites; i++){
        for(int j = 0; j<client_hello->length -37; j++){
            printf("\n %02X %02X ", buffer[i], client_hello->ciphersuite_code[0]);
            if(buffer[i] == client_hello->ciphersuite_code[j]){
                printf("\n\n");
                choosen = buffer[i];
                fclose(PriorityList);
                free(buffer);
                
                return choosen;
            }
            
        }
    }
    perror("\nError, uncompatibles chiphers\n");
    fclose(PriorityList);
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
    
    CipherList=NULL;
    buffer=NULL;

    CipherList = fopen(filename, "rb");
    
   	if (CipherList == NULL){
        perror("loadCipher error: memory allocation leak.");
        fclose(CipherList);
        exit(1);
    }
    
    fread(len, sizeof(uint8_t), 1, CipherList);
    buffer = (uint8_t *)malloc((*len)*sizeof(uint8_t));
    fread(buffer, (*len)*sizeof(uint8_t), 1, CipherList);
    fclose(CipherList);
    
    return buffer;    
}

/*************************************** OTHERS ******************************************************/

/**
 * Initialize and return the ciphersuite corresponding to the ciphersuite_code 
 * @param uint8_t ciphersuite_code
 * @return CipherSuite *cipher_suite
 */
CipherSuite *CodeToCipherSuite(uint8_t ciphersuite_code){
   
    CipherSuite *cipher_suite;
    cipher_suite=NULL;
    
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
