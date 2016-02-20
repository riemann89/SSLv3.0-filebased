#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/*****************************************STRUCTS***********************************************/

// HANDSHAKE STRUCTS //

typedef enum{
    HELLO_REQUEST,CLIENT_HELLO, SERVER_HELLO, CERTIFICATE=11,SERVER_KEY_EXCHANGE, CERTIFICATE_REQUEST, SERVER_DONE,CERTIFICATE_VERIFY, CLIENT_KEY_EXCHANGE,FINISHED=20
}HandshakeType;

typedef struct {
    HandshakeType msg_type;
    uint32_t length; //ToDo uint24
    uint8_t* content;
}HandshakeLayer;

typedef struct{
    /*ToDo typedef struct{
     uint32_t gmt_unix_time;
     uint8_t random_bytes[28];
     }Random;
     */
    //content
    uint8_t version;
    int random[4]; //-> ToDo RANDOM
    uint32_t sessionId;
    //Cipher_Suite_List ciphersuite[30]; // 30 because is the maximum number of supported cipher suites.
}ClientServerHello;

typedef struct{
    
}HelloRequest;

typedef struct{
    //ASN.1Cert certificate_list<1..2^24-1>;      ..non ho ben capito da fare quando si vedono i certificati
}Certificate;

typedef struct{
    //???? molto complicato
}ServerKeyExchange;

typedef enum{
    RSA_SIGN, DSS_SIGN, RSA_FIXED_DH,
    DSS_FIXED_DH,RSA_EPHEMERAL_DH, DSS_EPHEMERAL_DH,FORTEZZA_MISSI=20
}CertificateType;

typedef struct{
    CertificateType certificateTypes; // lo interpreto come un solo tipo anche se il nome suggerisce un plurale
    //DistinguishedName certificate_authorities<3..2^16-1>;  Probabilmente sarà più chiaro in seguito
}CertificateRequest;

typedef struct{
    //volutamente bianco la struttura è proprio così
}ServerHelloDone;

typedef struct{
    
}CertificateVerify;

typedef struct{
}ClientKeyExchange;

typedef struct{        //da rivedere non so come fare gli Hash #
    uint8_t sha_hash[20];
    uint8_t md5_hash[16];
    
}Finished;


// RECORD LAYER STRUCTS//

typedef struct {
    uint8_t major, minor;
}ProtocolVersion;

typedef enum{CHANGE_CIPHER_SPEC=20, ALERT, HANDSHAKE, APPLICATION_DATA
} ContentType;

typedef struct {
    ContentType type;
    ProtocolVersion version;
    uint16_t length;
    uint8_t* message;
}RecordLayer;










