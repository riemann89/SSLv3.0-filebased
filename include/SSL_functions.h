//PROTOTIPI DELLE FUNZIONI
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "structures.h"

//Connection function
void OpenCommunicationClient();
void OpenCommunicationServer();
int CheckCommunication(int talker);

//ClientServerHello send Function

void sendPacket(RecordLayer record_layer);

