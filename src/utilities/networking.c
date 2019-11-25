//networking functions
#include "networking.h"

//CHANNEL FUNCTIONS
/**
 * Gives to talker the right to write on the main channel,
 * It writes an ID on the file token.txt (0 - client, 1 - server, as defined in Talker enum)
 * @param Talker talker
 */
void OpenCommunication(Talker talker){
    FILE* token;
	
    //check the type of talker
    if (talker!=client && talker!=server) {
        perror("Error in OpenCommunication -  Error in talker input (nor client, nor server input)\n");
        exit(1);
    }
	
    //open the file token.txt and write who is authorized to communicate on the the file SSLchannelbyte.txt
    token = fopen("token.txt", "w");
    if(token == NULL){
        perror("Errore in apertura del file");
        exit(1);
    }
    fprintf(token,"%u",talker);
    fclose(token);
}

/**
 * It checks who between server/client can communicate. Return the rightful talker.
 * @return Talker authorized_talker
 */
Talker CheckCommunication(){
    FILE* token = NULL;
    Talker authorized_talker = 0;
    
    token = fopen("token.txt", "r");
    if(token == NULL) {
        perror("Failed to open token.txt - CheckCommunication() operation\n");
        exit(1);
    }
    
    // seek which is authorized to talk on the channel
    fscanf(token,"%u",&(authorized_talker));
    fclose(token);
    
    if (authorized_talker!=client && authorized_talker!=server) {
        perror("Error in token.txt - nor client,nor server authorized \n");
        exit(1);
    }
    return authorized_talker;
}


/**
 * This function loads a certificate from a file and return an array of bites 
 * where are contained certificate information in DER format
 * @param char *cert_name
 * @return Certificate *certificate
 */
Certificate* loadCertificate(char * cert_name){
    
    Certificate *certificate;
    X509* certificate_x509;
    uint8_t *buf;
    FILE* certificate_file;
    
    certificate = NULL;
    certificate_x509 = NULL;
    buf = NULL;
    certificate_file = NULL;
    int len = 0;
    
    certificate = (Certificate*)calloc(1, sizeof(Certificate));
    
    certificate_file = fopen(cert_name, "r");
    
    if (certificate_file == NULL){
        perror("Certificate File not found\n");
        exit(1);
    }
    
    certificate_x509 = PEM_read_X509(certificate_file, NULL, 0, NULL);
    len = i2d_X509(certificate_x509, &buf);
    
    certificate->X509_der = buf;
    certificate->len = len;
    
    fclose(certificate_file);
    X509_free(certificate_x509);
    
    return certificate;
}

/**
 * writes a record packet on SSLchannel.txt file
 * @param RecordLayer *record_layer
 */
void sendPacketByte(RecordLayer *record_layer){
    FILE* SSLchannel;
    uint8_t length16[4];
    
    SSLchannel = NULL;
    
    int_To_Bytes(record_layer->length, length16);

    SSLchannel = fopen("SSLchannelbyte.txt", "wb");
    
    if (SSLchannel == NULL) {
        perror("Failed to open SSLchannel.txt - sendPacket operation\n");							
        exit(1);
    }
    
    //writing record layer parameters on SSLchannel
    fwrite(&record_layer->type, sizeof(uint8_t), sizeof(uint8_t), SSLchannel);
    fwrite(&record_layer->version.major, sizeof(uint8_t), 1, SSLchannel);
    fwrite(&record_layer->version.minor, sizeof(uint8_t), 1, SSLchannel);
    fwrite(length16 + 2, sizeof(uint8_t), 2, SSLchannel);
    
    for (int i = 0; i<(record_layer->length-5); i++) {
        fwrite(record_layer->message + i, sizeof(uint8_t), 1, SSLchannel);
    }

    fclose(SSLchannel);
}

/**
 * Read the file SSLchannelbyte.txt and parse it into a record layer structure
 * @return RecordLayer *returning_record
 */
RecordLayer  *readchannel(){
    uint8_t *buffer;
    uint8_t record_header[5];
    FILE* SSLchannel;
    uint16_t packet_size;
    
    RecordLayer *returning_record;
    ProtocolVersion version;
    
    buffer = NULL;
    SSLchannel = NULL;
    returning_record = NULL;
    
    SSLchannel = fopen("SSLchannelbyte.txt", "rb");
    if(SSLchannel == NULL)
    {
        printf("Error unable to read the SSLchannel\n");
        exit(1);
    }
    
    fread(record_header, sizeof(uint8_t), 5*sizeof(uint8_t), SSLchannel);
    packet_size = Bytes_To_Int(2, record_header + 3);
    
    buffer = (uint8_t*)calloc(packet_size - 5, sizeof(uint8_t));
    fseek(SSLchannel, SEEK_SET, 5);
    fread(buffer, sizeof(uint8_t), (packet_size - 5)*sizeof(uint8_t), SSLchannel);// load file into buffer
    
    returning_record = calloc(1, sizeof(RecordLayer));
    
    returning_record->type = record_header[0];
    version.major = record_header[1];
    version.minor = record_header[2];
    returning_record->version = version;
    returning_record->length = packet_size;
    returning_record->message = buffer;
    
    fclose(SSLchannel);
    
    return returning_record;
}