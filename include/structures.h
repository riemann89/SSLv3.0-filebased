#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/*****************************************STRUCTS***********************************************/
// RECORD LAYER //

typedef struct {
    uint8_t major, minor;
} ProtocolVersion;

ProtocolVersion version = { 3,0 };

typedef enum {
    CHANGE_CIPHER_SPEC= 20, ALERT= 21, HANDSHAKE= 22, APPLICATION_DATA= 23,
} ContentType;

typedef struct {
    ContentType type;
    ProtocolVersion version;
    uint16_t length;
} SSLPlaintext;

// Non ho inserito le struct SSLCompressed, SSLCiphertext, GenericStreamCipher,
// GenericBlockCipher, ChangeCipherSpec, Alert
//Non ho inserito le enum AlertLevel, AlertDescription


//HANDSHAKE PROTOCOL//

typedef enum{
    hello_request = 0x00,
    client_hello,server_hello, certificate,server_key_exchange,
    certificate_request,server_hello_done,certificate_verify,client_key_exchange,finished
}HandshakeType;

extern short int Session_ID;

extern uint8_t cipher_Suite[2];

//HelloRequest

typedef struct{ }HelloRequestP;

//ClientHello
typedef struct
{
    int	version;
    int32_t random; //qui va sostituita la struct creata da ermes
    uint64_t session_Id;
    char CipherSuiteList;
}ClientHelloP;


//ServerHello
typedef struct
{
    int	version;
    int32_t random; //da modificare visto che ermes l'ha fatto come array di char
    uint64_t session_Id;
    char CipherSuiteList;
}ServerHelloP;



//CERTIFICATE
//RIV

//SERVER_KEY_EXCHANGE
//RIV

//CERTIFICATE_REQUEST

//SERVER_DONE
//RIV è null

//CERTIFICATE_VERIFY
//RIV signature

//CLIENT_KEY_EXCHANGE

//FINISHED
//RIV











