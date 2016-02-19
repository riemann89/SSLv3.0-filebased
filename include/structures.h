#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/*****************************************STRUCTS***********************************************/
// HANDSHAKE STRUCTS //

typedef enum{
    HELLO_REQUEST,CLIENT_HELLO, SERVER_HELLO, CERTIFICATE=11,SERVER_KEY_EXCHANGE, CERTIFICATE_REQUEST, SERVER_DONE,CERTIFICATE_VERIFY, CLIENT_KEY_EXCHANGE,FINISHED=20
}HandshakeType;

typedef struct{
    uint8_t ciphersuite[2];
}CipherSuite;

typedef struct{
    HandshakeType msg_type;
    uint32_t length; //ToDo uint24
}Handshake;

typedef struct{
    Handshake handshake_header;
    
    //content
    uint8_t version;
    int random[4]; //-> ToDo RANDOM
    uint32_t sessionId;
    CipherSuite ciphersuite;
}ClientServerHello;

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










