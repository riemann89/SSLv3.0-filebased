//PROTOTIPI DELLE FUNZIONI
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "structures.h"
#include "Utilities.h"

//Connection function
void OpenCommunicationClient();
void OpenCommunicationServer();
int CheckCommunication(int talker);
void sendPacket(RecordLayer record_layer);

//ClientHello
uint8_t* ClientServerHelloToBytes(ClientServerHello* client_server_hello);


//ClientServerHello send Function



