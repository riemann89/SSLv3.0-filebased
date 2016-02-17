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

