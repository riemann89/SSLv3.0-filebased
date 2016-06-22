#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "openssl/x509.h"
#include "openssl/pem.h"
#include <openssl/bio.h>
#include <openssl/err.h>

/*****************************************STRUCTS***********************************************/
#ifndef structure_h
#define structure_h

//OTHER STRUCTS
typedef enum{client, server
}Talker;

// HANDSHAKE STRUCTS //

typedef enum{
    HELLO_REQUEST,CLIENT_HELLO, SERVER_HELLO, CERTIFICATE=11,SERVER_KEY_EXCHANGE, CERTIFICATE_REQUEST, SERVER_DONE,CERTIFICATE_VERIFY, CLIENT_KEY_EXCHANGE,FINISHED=20
}HandshakeType;

typedef struct{
    uint8_t code;
    char name[50];
}CipherSuite;

typedef struct {
    HandshakeType msg_type;
    uint32_t length;
    uint8_t* content;
}Handshake;

typedef struct{
    uint32_t gmt_unix_time;
    uint8_t random_bytes[28];
}Random;

//content
typedef struct{
    uint8_t length;  //uint8_t beacause the maximum length will < 256;    38 + #ciphersuite*4 ,   WARNING: in the handshake there will be no more this byite 
    uint8_t version;
    Random random;
    uint32_t sessionId;
    CipherSuite *ciphersuite; 
}ClientServerHello;

typedef struct{
    
}HelloRequest;

typedef struct{
    //ASN.1Cert certificate_list<1..2^24-1>; (RIV)
    uint8_t *X509_der;
    int len;
}Certificate;

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
    uint8_t *parameters;
    uint8_t *signature;
}ServerKeyExchange;

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

//Structs for ServerKeyExchange
typedef enum{RSA_, DIFFIE_HELLMAN, FORTEZZA}KeyExchangeAlgorithm;

typedef struct {
    uint8_t rsa_modulus[2^16-1];
    uint8_t rsa_exponent[2^16-1];
}ServerRSAParams;

typedef struct {
    uint8_t dh_p[2^16-1];
    uint8_t dh_g[2^16-1];
    uint8_t dh_Ys[2^16-1];
}ServerDHParams;

typedef struct{
    uint8_t r_s[128];
}ServerFortezzaParams;

//Extern variables
extern CipherSuite lista[31];
extern ProtocolVersion std_version;

CipherSuite get_cipher_suite(uint8_t id);
#endif







