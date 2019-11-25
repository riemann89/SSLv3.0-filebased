#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "openssl/x509.h"
#include "openssl/pem.h"

#include "structures.h"
#include "utilities.h"
#include "crypto_binding.h"

/* PACKET MANAGING */

//message -> handshake
Handshake *HelloRequestToHandshake();
Handshake *ClientServerHelloToHandshake(ClientServerHello *client_server_hello);
Handshake *CertificateToHandshake(Certificate *certificate);
Handshake *CertificateRequestToHandshake(CertificateRequest *certificate_request);
Handshake *ServerDoneToHandshake();
Handshake *CertificateVerifyToHandshake(CertificateVerify *certificate_verify);
Handshake *ClientKeyExchangeToHandshake(ClientKeyExchange *client_key_exchange);
Handshake *ServerKeyExchangeToHandshake(ServerKeyExchange *server_key_exchange);
Handshake *FinishedToHandshake(Finished *finished);

// hanshake -> message
HelloRequest *HandshakeToHelloRequest(Handshake *handshake);
ClientServerHello *HandshakeToClientServerHello(Handshake *handshake);
Certificate *HandshakeToCertificate(Handshake *handshake);
CertificateRequest *HandshakeToCertificateRequest(Handshake *handshake);
ServerDone *HandshakeToServerdone(Handshake *handshake);
CertificateVerify *HandshakeToCertificateVerify(Handshake *handshake);
ClientKeyExchange *HandshakeToClientKeyExchange(Handshake *handshake);
ServerKeyExchange *HandshakeToServerKeyExchange(Handshake *handshake, Certificate *certificate);
Finished *HandshakeToFinished(Handshake *handshake);

// record -> handshake
Handshake *RecordToHandshake(RecordLayer *record);

//handshake -> record
RecordLayer *HandshakeToRecordLayer(Handshake *handshake);

//change cipher spec protocol
RecordLayer *ChangeCipherSpecRecord();

//print package
void printRecordLayer(RecordLayer *record_layer);

/* CIPHERSUITE */
uint8_t *loadCipher(char* filename , uint8_t *len);
CipherSuite *CodeToCipherSuite(uint8_t ciphersuite_code);
uint8_t chooseChipher(ClientServerHello *client_hello, char *filename);

/* INIT FUNCTIONS*/
ClientServerHello *ClientServerHello_init(HandshakeType type, uint32_t sessionId, uint8_t *ciphersuite_code, uint8_t ciphersuite_code_len);
ClientKeyExchange *ClientKeyExchange_init(CipherSuite *ciphersuite, Certificate *certificate, ServerKeyExchange *server_key_exchange, uint8_t **premaster_secret, int *premaster_secret_size);
ServerKeyExchange *ServerKeyExchange_init(CipherSuite *ciphersuite, EVP_PKEY *private_key, ClientServerHello *client_hello, ClientServerHello *server_hello, DH **dh);
Certificate *Certificate_init(CipherSuite *ciphersuite);   

/* FREE FUNCTIONS */
void FreeRecordLayer(RecordLayer *recordLayer);
void FreeHandshake(Handshake *handshake);
void FreeClientServerHello(ClientServerHello *client_server_hello);
void FreeCertificate(Certificate *certificate);
void FreeCertificateVerify(CertificateVerify *certificate_verify);
void FreeServerHelloDone(ServerDone *server_done);
void FreeFinished(Finished *finished);
void FreeClientKeyExchange(ClientKeyExchange *client_key_exchange);
void FreeServerKeyExchange(ServerKeyExchange *server_key_exchange);
