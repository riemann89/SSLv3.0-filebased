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
Handshake *ClientKeyExchangeToHandshake(ClientKeyExchange *client_key_exchange); //TODO: va adattato per il server_client_exchange eventualmente
Handshake *FinishedToHandshake(Finished *finished);

// hanshake -> message
HelloRequest *HandshakeToHelloRequest(Handshake *handshake);
ClientServerHello *HandshakeToClientServerHello(Handshake *handshake);
Certificate *HandshakeToCertificate(Handshake *handshake);
ClientKeyExchange *HandshakeToClientKeyExchange(Handshake *handshake, KeyExchangeAlgorithm algorithm_type, uint32_t len_parameters);
CertificateRequest *HandshakeToCertificateRequest(Handshake *handshake);
ServerDone *HandshakeToServerdone(Handshake *handshake);
CertificateVerify *HandshakeToCertificateVerify(Handshake *handshake);
ServerKeyExchange *HandshakeToServerKeyExchange(Handshake *handshake, KeyExchangeAlgorithm algorithm_type, SignatureAlgorithm signature_type, uint32_t len_parameters, uint32_t len_signature);
Finished *HandshakeToFinished(Handshake *handshake);

// record -> handshake
Handshake *RecordToHandshake(RecordLayer *record);

//handshake -> record
RecordLayer *HandshakeToRecordLayer(Handshake *handshake);

//change cipher spec protocol
RecordLayer *ChangeCipherSpecRecord();

/* CIPHERSUITE */
void setPriorities(uint8_t *number, CipherSuite *priority, char *filename);
CipherSuite *loadCipher(char* filename , uint8_t *len);
CipherSuite2 *CodeToCipherSuite(uint8_t ciphersuite_code);
uint8_t chooseChipher(ClientServerHello *client_supported_list, char *filename);


/* FREE FUNCTIONS */

void FreeRecordLayer(RecordLayer *recordLayer);

void FreeHandshake(Handshake *handshake);

void FreeClientServerHello(ClientServerHello *client_server_hello);
void FreeCertificate(Certificate *certificate);
void FreeCertificateVerify(CertificateVerify *certificate_verify);
void FreeServerHelloDone(ServerDone *server_done);
void FreeCertificateFinished(Finished *finished);
void FreeClientKeyExchange(ClientKeyExchange *client_key_exchange);

/* CERTIFICATE */
Certificate* loadCertificate(char * cert_name);
int writeCertificate(X509* certificate);
EVP_PKEY* readCertificateParam (Certificate *certificate);

/* KEY BLOCK*/

uint8_t *BaseFunction(int numer_of_MD5, uint8_t* principal_argument, int principal_argument_size, ClientServerHello *client_hello, ClientServerHello *server_hello);

uint8_t *MasterSecretGen(uint8_t *pre_master_secret, ClientServerHello *client_hello, ClientServerHello *server_hello);

uint8_t *KeyBlockGen(uint8_t *master_secret, CipherSuite2 *cipher_suite, ClientServerHello *client_hello, ClientServerHello *server_hello);

/* ENCRYPTION */

//asymmetric
uint8_t *encryptPreMaster(EVP_PKEY *pKey, KeyExchangeAlgorithm algorithm, uint8_t* pre_master_secret);
uint8_t *decryptPreMaster(KeyExchangeAlgorithm alg, uint8_t *enc_pre_master_secret);

//symmetric
uint8_t* DecEncryptPacket(uint8_t *packet, int packet_len, uint8_t *enc_packet_len, CipherSuite2 *cipher_suite, uint8_t* key_block, Talker key_talker, int state);

/* AUTHENTICATION */
uint8_t* MAC(CipherSuite2 cipher, Handshake *hand, uint8_t* macWriteSecret);

