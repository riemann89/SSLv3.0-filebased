#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "structures.h"
#include "Utilities.h"
#include "openssl/x509.h"
#include "openssl/pem.h"

/* CONNECTION */

void OpenCommunication(Talker talker);
Talker CheckCommunication();
void sendPacketByte(RecordLayer *record_layer);
RecordLayer *readchannel();

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
void printHandshake(Handshake *handshake);

/* CIPHERSUITE */
uint8_t *loadCipher(char* filename , uint8_t *len);
CipherSuite *CodeToCipherSuite(uint8_t ciphersuite_code);
CertificateType CodeToCertificateType(uint8_t ciphersuite_code);
uint8_t chooseChipher(ClientServerHello *client_supported_list, char *filename);
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

/* CERTIFICATE */
Certificate* loadCertificate(char * cert_name);
void writeCertificate(X509* certificate);
EVP_PKEY* readCertificateParam (Certificate *certificate);
DH *get_dh2048();

/* KEY BLOCK*/

uint8_t *BaseFunction(int numer_of_MD5, uint8_t* principal_argument, int principal_argument_size, ClientServerHello *client_hello, ClientServerHello *server_hello);
uint8_t *MasterSecretGen(uint8_t *pre_master_secret, int pre_master_len, ClientServerHello *client_hello, ClientServerHello *server_hello);
uint8_t *KeyBlockGen(uint8_t *master_secret, CipherSuite *cipher_suite, int *size, ClientServerHello *client_hello, ClientServerHello *server_hello);

/* ENCRYPTION */

//asymmetric
uint8_t* AsymEnc(EVP_PKEY *public_key, uint8_t* plaintext, size_t inlen, size_t *outlen);
uint8_t* AsymDec(int private_key_type, uint8_t *ciphertext, size_t inlen, size_t *outlen, EVP_PKEY *private_key);

//symmetric
uint8_t* DecEncryptPacket(uint8_t *in_packet, int in_packet_len, int *out_packet_len, CipherSuite *cipher_suite, uint8_t* key_block, Talker key_talker, int state);

/* AUTHENTICATION */
uint8_t* MAC(CipherSuite *cipher, Handshake *hand, uint8_t* macWriteSecret);
uint8_t* Signature_(CipherSuite *cipher, ClientServerHello *client_hello, ClientServerHello *server_hello, uint8_t* params, int len_params, EVP_PKEY *pKey);
void Verify_(CipherSuite *cipher, ClientServerHello *client_hello, ClientServerHello *server_hello, uint8_t* params, int len_params, uint8_t *signature, int len_signature, Certificate *certificate);

