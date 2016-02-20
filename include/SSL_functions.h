//PROTOTIPI DELLE FUNZIONI
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "structures.h"

//Connection function
void OpenCommunicationClient();
void OpenCommunicationServer();
int CheckCommunication(int talker);
void sendPacket(RecordLayer record_layer);

//ClientHello
bool acquisionCS(ClientServerHello *client_hello);


//ClientServerHello send Function



