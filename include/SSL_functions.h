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

void sendClient_Server_hello(RecordLayer record_layer, ClientServerHello client_server_hello);
bool readClient_Server_hello();

