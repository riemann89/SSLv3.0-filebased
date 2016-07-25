#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "structures.h"
#include "Utilities.h"
#include <openssl/x509.h>
#include <openssl/pem.h>

//Connection
void OpenCommunication(Talker talker);
Talker CheckCommunication();
void sendPacketByte(RecordLayer *record_layer);

//PACKET MANAGER
//message->handshake
Handshake *HelloRequestToHandshake();
Handshake *ClientServerHelloToHandshake(ClientServerHello *client_server_hello);
Handshake *CertificateToHandshake(Certificate *certificate);
Handshake *ServerClientKeyExchangeToHandshake(ServerKeyExchange *server_key_exchange);
Handshake *CertificateRequestToHandshake(CertificateRequest *certificate_request);
Handshake *ServerDoneToHandshake();
Handshake *CertificateVerifyToHandshake(CertificateVerify *certificate_verify);
Handshake *ClientKeyExchangeToHandshake(ClientKeyExchange *client_key_exchange);
Handshake *FinishedToHandshake(Finished *finished);

/* Handshake to message types */

HelloRequest *HandshakeToHelloRequest(Handshake *handshake);//TODO
ClientServerHello *HandshakeToClientServerHello(Handshake *handshake);//TODO
Certificate *HandshakeToCertificate(Handshake *handshake);//TODO
ServerKeyExchange *HandshakeToServerKeyExchange(Handshake *handshake);//TODO
CertificateRequest *HandshakeToCertificateRequest(Handshake *handshake);//TODO
ServerDone *HandshakeToServerdone(Handshake *handshake);//TODO
CertificateVerify *HandshakeToCertificateVerify(Handshake *handshake);//TODO
ClientKeyExchange *HandshakeToClientKeyExchange(Handshake *handshake);//TODO
Finished *HandshakeToFinished(Handshake *handshake);//TODO

//record->handshake
Handshake *RecordToHandshake(RecordLayer *record);  //TOCHECK GIUSEPPE


//Record Layer Protocol
RecordLayer *HandshakeToRecordLayer(Handshake *handshake);  
RecordLayer *readchannel2();  //TODO    1 sostituire con readchannel()


ClientServerHello *readchannel();//TODO  4  da sostituire con HandshakeToHello( Handshake *handshake);
ClientServerHello HandshakeToHello(Handshake *handshake);  // TODO 3
void setPriorities(uint8_t number,uint8_t *priority);
ClientServerHello *makeServerHello();
uint8_t chooseChipher(ClientServerHello *client_supported_list);

//TODO free functions
void FreeRecordLayer(RecordLayer *recordLayer);
void FreeHandshake(Handshake *handshake);
void FreeClientServerHello(ClientServerHello *client_server_hello);
void FreeCertificate(Certificate *certificate);
void FreeCertificateVerify(CertificateVerify *certificate_verify);
void FreeServerHelloDone(ServerDone *server_done);
void FreeCertificateFinished(Finished *finished);
void FreeClientKeyExchange(ClientKeyExchange *client_key_exchange);

//CERTIFICATE
Certificate* loadCertificate(char * cert_name);
int writeCertificate(X509* certificate);
