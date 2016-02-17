#include "SSL_functions.h"

/*****************************************FUNCTIONS***********************************************/

//CHANNEL FUNCTIONS

//Allows the Client communication #T 
void OpenCommunicationClient(){
	int	reading_flag=1;
	FILE* token;

	token=fopen("token.txt", "w");
	if(token == NULL) {
		perror("Errore in apertura del file");
		exit(1);
	}
	fprintf(token,"%d",reading_flag);
    fflush(token);
	fclose(token);
}

//Allows the Server communication #T
void OpenCommunicationServer(){
	int	reading_flag=0;
	FILE* token;

	token=fopen("token.txt", "w");
	if(token == NULL) {
		perror("Errore in apertura del file");
		exit(1);
	}

	fprintf(token,"%d",reading_flag);
    fflush(token);
	fclose(token);

}

/*Check if Server/Client can communicate. #T
Input "0" indicates ClientChecker, "1" indicates ServerChecker
return "1" if talker can communicate, "0" otherwise.
*/
int CheckCommunication(int talker){
	FILE* token;
	int reading_flag = 0;
	
	switch (talker){
		case 0: 
		token=fopen("token.txt", "r");
		if(token == NULL) {
			perror("Errore in apertura del file");
			exit(1);
		}
		fscanf(token,"%d",&reading_flag);
		fclose(token);
		if (reading_flag == 1)
			return 1;
        break;
        
		case 1:
		token=fopen("token.txt", "r");
		if(token == NULL) {
			perror("Errore in apertura del file");
			exit(1);
		}
		fscanf(token,"%d",&reading_flag);
		fclose(token);
		if (reading_flag == 0)
			return 1;
	}
	return 0;
}

//RECORD PROTOCOL FUNCTIONS

void RecordProtocol(ContentType contenttype, uint16_t length){
FILE* canale;
//Fragmentation 
//Compression 
//MAC
//ENCRYPT
//ADDING HEADER

//Fase di scrittura
canale=fopen("canaleSSL.txt", "w");
if(canale == NULL) {
			perror("Errore in apertura del file");
			exit(1);
		}
fprintf(canale,"%x",contenttype);
fclose(canale);

}

//HANDSHAKE FUNCTIONS

void HelloRequestF(){};

void ClientHelloF(){};

void ServerHelloF(){};

void CertificateF(){};

void ServerKeyExchangeF(){};

void CertificateRequestF(){};

void ServerDoneF(){};

void CertificateVerifyF(){};

void ClientKeyExchangeF(){};

void FinishedF(){};


//Handshake main function - 
//a seconda del tipo di pacchetto da inviare sul canale, richiama la funzione corrispondente.


void Handshake(HandshakeType handshaketype){
    switch (handshaketype){
        case 0:
            HelloRequestF();
            break;
        case 1:ClientHelloF();
            break;
        case 2:ServerHelloF();
            break;
        case 3:CertificateF();
            break;
        case 4:ServerKeyExchangeF();
            break;
        case 5:CertificateRequestF();
            break;
        case 6:ServerDoneF();
            break;
        case 7:CertificateVerifyF();
            break;
        case 8:ClientKeyExchangeF();
            break;
        case 9:FinishedF();
            break;
        default:
            break;
    }
};




