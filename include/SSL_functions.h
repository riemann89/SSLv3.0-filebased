#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "structures.h"
#include "Utilities.h"

//Connection
void OpenCommunication(Talker talker);
Talker CheckCommunication();
int sendPacket(RecordLayer *record_layer);

//Packet Encapsulation
Handshake *ClientServerHelloToHandshake(ClientServerHello *client_server_hello);
RecordLayer *HandshakeToRecordLayer(Handshake *handshake);
Handshake *ServerDoneToHandshake();




