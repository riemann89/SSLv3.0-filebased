#include "structures.h"
#include "utilities.h"

// networking functions
void OpenCommunication(Talker talker);
Talker CheckCommunication();
Certificate* loadCertificate(char * cert_name); //TODO to move
void sendPacketByte(RecordLayer *record_layer);
RecordLayer  *readchannel();