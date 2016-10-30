#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/*****************************************STRUCTS***********************************************/
#ifndef structure_h
#define structure_h

//OTHER STRUCTS
typedef enum{client = 0x434C4E54, server = 0x53525652
}Talker;

// HANDSHAKE STRUCTS //

typedef enum{
    HELLO_REQUEST, CLIENT_HELLO, SERVER_HELLO, CERTIFICATE = 11, SERVER_KEY_EXCHANGE, CERTIFICATE_REQUEST, SERVER_DONE, CERTIFICATE_VERIFY, CLIENT_KEY_EXCHANGE, FINISHED=20
}HandshakeType;

typedef enum{
    KNULL, RSA_, DH_, KFORTEZZA
}KeyExchangeAlgorithm;

typedef enum {
    TNULL, STREAM, BLOCK
} CipherType;

typedef enum{
    RSA_SIGN, DSS_SIGN,
    RSA_FIXED_DH, DSS_FIXED_DH,
    RSA_EPHEMERAL_DH, DSS_EPHEMERAL_DH,
    DH_ANON, FORTEZZA_MISSI = 20
}CertificateType;

typedef enum{
    CNULL, RC4, RC2, IDEA, DES, DES3, DES40, FORTEZZA
}CipherAlgorithm;//TODO: completare

typedef enum{
    HNULL, SHA1_, MD5_1
}HashAlgorithm;

typedef enum{
    SNULL, RSA_s, DSA_s, FORTEZZA_s
}SignatureAlgorithm;

typedef struct{
    KeyExchangeAlgorithm key_exchange_algorithm;
    CipherType cipher_type;
    CipherAlgorithm cipher_algorithm;
    uint8_t iv_size;
    uint8_t key_material;
    HashAlgorithm hash_algorithm;
    SignatureAlgorithm signature_algorithm;
    uint8_t hash_size;
    _Bool exportable;
}CipherSuite;

typedef struct {
    HandshakeType msg_type;
    uint32_t length;   //on file it will be  only 3 bytes (uint24)  so remember to convert
    uint8_t* content;
}Handshake;

typedef struct{
    uint32_t gmt_unix_time;
    uint8_t random_bytes[28];
}Random;

//content
typedef struct{
    uint8_t length;
    uint8_t version;
    Random *random;
    uint32_t sessionId;
    uint8_t *ciphersuite_code;
    HandshakeType type;
}ClientServerHello;

typedef struct{
}HelloRequest;

typedef struct{
    const uint8_t *X509_der;
    uint32_t len;
}Certificate;

typedef struct{
    CertificateType certificate_type;
    char *certificate_authorities;
    int name_lenght;    //each certificate authority name is represented using the same number of char.
    int list_length;    //number of certificate of acceptable certificate authorities.
}CertificateRequest;//TODO la struttura deve essere rivista

typedef struct{
}ServerDone;

typedef struct{
    HashAlgorithm algorithm_type;
    uint8_t *signature;
}CertificateVerify;

typedef struct{
    uint8_t *hash;
}Finished;


// RECORD LAYER STRUCTS//

typedef struct {
    uint8_t major, minor;
}ProtocolVersion;

typedef enum{
    CHANGE_CIPHER_SPEC=20, ALERT, HANDSHAKE, APPLICATION_DATA
} ContentType;

typedef struct {
    ContentType type;
    ProtocolVersion version;
    uint16_t length;
    uint8_t* message;
}RecordLayer;

//Structs for ServerKeyExchange

typedef struct{
    uint8_t *parameters;
    size_t len_parameters;
}ClientKeyExchange;

typedef struct{
    uint8_t *parameters;
    uint8_t *signature;
    uint32_t len_parameters;
    uint32_t len_signature;
}ServerKeyExchange;

//Extern variables
extern uint8_t lista[31];
extern uint8_t lista2[8];
extern uint8_t pad_1[48];
extern uint8_t pad_2[48];
extern ProtocolVersion std_version;

#endif







