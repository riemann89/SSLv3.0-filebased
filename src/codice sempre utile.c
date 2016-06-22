TEST FUNZIONAMENTO:

Packet Function

RecordLayer recordlayer_clienthello;
recordlayer_clienthello.type=HANDSHAKE;
recordlayer_clienthello.version.major=3;
recordlayer_clienthello.version.minor=0;
recordlayer_clienthello.length=3;
uint8_t message[]={12,34,56};
recordlayer_clienthello.message=message;
sendPacket(recordlayer_clienthello);


/*
    //Leggi configurazione:
    FILE* canaleSSL;
    char a='c';
    
    for (int i=0; i<10; i++) {
        while(CheckCommunication(1)!=0){
            usleep(100);
        };
        
        canaleSSL=fopen("canaleSSL.txt", "a+");
        if(canaleSSL == NULL) {
            perror("Errore in apertura del file");
            exit(1);
        }
        fprintf(canaleSSL,"%c",a);
        fclose(canaleSSL);
        
        OpenCommunicationServer();
    }
    OpenCommunicationClient();
    //SCRIVO
    
    
    //Hello Client
    //RecordProtocol(alert, 2);
     */
    
    //CipherSuite test={0x01,0x10};


//ClientServerHello client_hello;
//RecordLayer record_client_hello;
//CipherSuite cipher_suite_client;
/*
client_hello.type=CLIENT_HELLO;

client_hello.version=3;

client_hello.random[0]=0;
client_hello.random[1]=0;
client_hello.random[2]=0;
client_hello.random[3]=0;

client_hello.sessionId=123;

//leggo cipher suite;
uint cs1;
uint cs2;

FILE* file_suite;
file_suite=fopen("cipher_suite_list_client1.txt", "r");
fscanf(file_suite,"%x %x",&cs1,&cs2);
fclose(file_suite);
printf("%04x\n",cs1);
printf("%#08x\n",cs2);
*/


    Random ran;
    int i;
    ran.gmt_unix_time=35;
    uint8_t array[28]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28};
    ran.random_bytes=array;
    ClientServerHello cli;
    cli.random=ran;
    cli.sessionId=55;
    cli.version=3;
    cli.ciphersuite=lista;
    cli.length=69;
    
    uint8_t* pointer;
    pointer=ClientServerHelloToBytes(cli);
    for(i=0;i<69;i++){
        printf("%02x",*(pointer+i));
    }
    printf("\n");
    return 0;




//test del clienthello sul file

   Random ran;
    ran.gmt_unix_time=35;
    uint8_t array[28]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28};
	
	uint8_t *randarray;
	randarray=&ran.random_bytes;

	for(int i =0;i<28;i++)  ran.random_bytes[i] =array[i]; 
      //QUI NON RUNNA PERCHE' ABBIAMO CAMBIATO IL PUNTATORE DEL RANDOM ToDo
    ClientServerHello cli;
    ClientServerHello* p_cli;
    p_cli=&cli;
    cli.random=ran;
    cli.sessionId=55;
    cli.version=3;
    cli.ciphersuite=lista;
    cli.length=69;
    
    Handshake
    Handshake *handshake;
   
    
  handshake=ClientServerHelloToHandshake(p_cli); 
  
  
	
	
    RecordLayer *recordlayer;
    recordlayer=HandshakeToRecordLayer(handshake);
    
    sendPacket(*recordlayer);

int sendPacket(RecordLayer *record_layer){

//Variables Declarations//
FILE* SSLchannel;
uint8_t length16[4];
int_To_Bytes(record_layer->length, length16);

//Channel Operations//
//channel opening in creating-writing mode
SSLchannel=fopen("SSLchannel.txt", "wb");
if (SSLchannel == NULL) {
perror("Failed to open SSLchannel.txt - sendPacket operation");
exit(1);
}

//record_layer fields writing phase
fprintf(SSLchannel,"%02x\n",record_layer->type);
fprintf(SSLchannel,"%02x\n",record_layer->version.major);
fprintf(SSLchannel,"%02x\n",record_layer->version.minor);
fprintf(SSLchannel, "%02x %02x\n",length16[2],length16[3]);
for (int i=0; i<(record_layer->length-5); i++) {
fprintf(SSLchannel, "%02x ",record_layer->message[i]);
}

//channel closure
fclose(SSLchannel);
return 1;
}



//RSA funzionamento base:



