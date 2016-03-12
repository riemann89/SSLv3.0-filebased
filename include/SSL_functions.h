#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "structures.h"
#include "Utilities.h"

//Connection
void OpenCommunication(Talker talker);
Talker CheckCommunication();
void sendPacketByte(RecordLayer *record_layer);

//Packet Encapsulation
Handshake *ClientServerHelloToHandshake(ClientServerHello *client_server_hello);

//ClientHello
//uint8_t* ClientServerHelloToBytes(ClientServerHello* client_server_hello);
Handshake* ClientServerHelloToHandshake(ClientServerHello* client_server_hello);
Handshake* ServerDoneToHandshake();

RecordLayer *HandshakeToRecordLayer(Handshake *handshake);


ClientServerHello *readchannel();
void setPriorities(uint8_t number,uint8_t *priority);
ClientServerHello *makeServerHello();
uint8_t chooseChipher(ClientServerHello *client_supported_list);


