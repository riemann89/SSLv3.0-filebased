//PROTOTIPI DELLE FUNZIONI
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "structures.h"

void OpenCommunicationClient();
void OpenCommunicationServer();
int CheckCommunication(int talker);

void Handshake(HandshakeType handshaketype);
void HelloRequestF();
void ClientHelloF();
void ServerHelloF();
void Certificate();
void ServerKeyExchange();
void ServerDone();
void CertificateVerify();
void ClientKeyExchange();
void Finished();


void RecordProtocol(ContentType contenttype, uint16_t length);
