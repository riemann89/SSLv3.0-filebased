#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include "SSL_functions.h"


int main(int argc, const char *argv[]){
    //Declaration
    ClientServerHello client_hello, *server_hello;
    Handshake *handshake, *server_handshake;
    RecordLayer *record, *server_message, *temp,record2;
    Random random;
    ClientKeyExchange client_key_exchange;
    ServerKeyExchange *server_key_exchange;
    Certificate *certificate;
    CertificateRequest *certificate_request;
    Finished finished;
    CertificateType certificate_type;
    Talker sender;
    int pre_master_secret_size;
    EVP_PKEY * pubkey;
    RSA * rsa;
    uint32_t len_parameters;
    int phase, key_block_size,enc_message_len,dec_message_len;
    uint8_t *pre_master_secret, *pre_master_secret_encrypted, *master_secret,*sha_1,*md5_1, *sha_fin, *md5_fin, *iv, *cipher_key;
    MD5_CTX md5;
    SHA_CTX sha;
    uint32_t sender_id;
    uint8_t len_hello, *key_block;
    uint8_t *supported_ciphers,*enc_message, *dec_message,*mac, *client_write_MAC_secret[16];
    DH *dh = NULL;
    BIGNUM *pub_key_server;
    size_t out_size;
    CipherSuite *cipher_suite_choosen;
    int p_size;
    
    
    //Initialization
    pre_master_secret_size = 0;
    out_size = 0;
    dec_message_len = 0;
    dec_message = NULL;
    enc_message_len = 0;
    enc_message=NULL;
    server_hello = NULL;
    handshake = NULL;
    server_handshake = NULL;
    record = NULL;
    server_message = NULL;
    certificate = NULL;
    certificate_request = NULL;
    pubkey = NULL;
    rsa = NULL;
    pre_master_secret = NULL;
    pre_master_secret_encrypted = NULL;
    master_secret = NULL;
    key_block = NULL;
    iv = NULL;
    cipher_key = NULL;
    len_parameters = 0;
    len_hello = 0;
    phase = 0;
    key_block_size = 0;
    certificate_type = 0;
    temp = NULL;
    sender = client;
    SHA1_Init(&sha);
    MD5_Init(&md5);
    server_key_exchange= NULL;
    
    ///////////////////////////////////////////////////////////////PHASE 1//////////////////////////////////////////////////////////
    OpenCommunication(client);
    
    
    //Construction Client Hello
    random.gmt_unix_time = (uint32_t)time(NULL);
    RAND_bytes(random.random_bytes, 28);
    
    client_hello.version = 3;
    client_hello.random = &random;
    client_hello.type = CLIENT_HELLO;
    client_hello.sessionId = 0;
    supported_ciphers = loadCipher("ClientConfig/Priority3.txt", &len_hello);
    client_hello.length = 38 + len_hello;
    client_hello.ciphersuite_code = supported_ciphers;
    //modifica per inserire velocemente ciphers da clienthello cancellare le 3 rige seguenti per tornare al modello vecchio
    supported_ciphers = NULL;
    supported_ciphers[0] = 5;   //inserire il codice corrispondente alla ciphers voluta
    client_hello.ciphersuite_code = supported_ciphers;
    sender_id = client_hello.sessionId;
    
    //Wrapping
    handshake = ClientServerHelloToHandshake(&client_hello);
    record = HandshakeToRecordLayer(handshake);
    
    //Sending client hello
    sendPacketByte(record);
    printRecordLayer(record);
	

    SHA1_Update(&sha, record->message, sizeof(uint8_t)*(record->length-5));
    MD5_Update(&md5, record->message, sizeof(uint8_t)*(record->length-5));
    
    FreeRecordLayer(record);
    FreeHandshake(handshake);
    
    //Opening the communication to the server and, when authorized, reading server hello
    OpenCommunication(server);
    while(CheckCommunication() == server){}
    
    server_message = readchannel();
    printRecordLayer(server_message);
    server_handshake = RecordToHandshake(server_message);
    server_hello = HandshakeToClientServerHello(server_handshake);
    
    SHA1_Update(&sha, server_message->message, sizeof(uint8_t)*(server_message->length-5));
    MD5_Update(&md5, server_message->message, sizeof(uint8_t)*(server_message->length-5));
    
    FreeRecordLayer(server_message);
    FreeHandshake(server_handshake);
    /*
    cipher_suite_choosen = CodeToCipherSuite(server_hello->ciphersuite_code[0]);
    certificate_type = CodeToCertificateType(server_hello->ciphersuite_code[0]);
	*/
    cipher_suite_choosen = CodeToCipherSuite(0x14); //TODO: riga su...
    certificate_type = CodeToCertificateType(0x14);//TODO: automatizzare
    
    OpenCommunication(server);
    phase = 2;
    ///////////////////////////////////////////////////////////////PHASE 2//////////////////////////////////////////////////////////
    while(phase == 2){
        while(CheckCommunication() == server){}
        //Per come è strutturato non possiamo evitare l'invio reiterato dello stesso messaggio e di sequenze sbagliate di messaggi TODO ?
        
        server_message = readchannel();
        printRecordLayer(server_message);
        server_handshake = RecordToHandshake(server_message);
        
        switch (server_handshake->msg_type) {
            case CERTIFICATE:
                certificate = HandshakeToCertificate(server_handshake);
                
                SHA1_Update(&sha,server_message->message,sizeof(uint8_t)*(server_message->length-5));
                MD5_Update(&md5,server_message->message,sizeof(uint8_t)*(server_message->length-5));
                
                pubkey = readCertificateParam(certificate);
                
                FreeRecordLayer(server_message);
                FreeHandshake(server_handshake);
                
                OpenCommunication(server);
                break;
            case SERVER_KEY_EXCHANGE:

                server_key_exchange = HandshakeToServerKeyExchange(server_handshake,cipher_suite_choosen);
                //TODO: controllo della firma
                //.........................
                
                SHA1_Update(&sha, server_message->message, sizeof(uint8_t)*(server_message->length-5));
                MD5_Update(&md5, server_message->message, sizeof(uint8_t)*(server_message->length-5));
                
                len_parameters = server_handshake->length - 4 - cipher_suite_choosen->hash_size;
                p_size = (len_parameters - 1)/2;
                
                pub_key_server = BN_new();
                dh = DH_new();
                
            	dh-> p = BN_bin2bn(server_key_exchange->parameters, p_size, NULL);
                dh-> g = BN_bin2bn(server_key_exchange->parameters + p_size, 1, NULL);
                if(DH_generate_key(dh) == 0){
                    perror("DH keys generation error.");
                    exit(1);
                }
                
                pub_key_server = BN_bin2bn(server_key_exchange->parameters + p_size + 1, p_size, NULL);
                ///////////////////
                //check signature
                //////////////////
                _Bool verify;
                int len_signature = p_size; //TODO: da automatizzare
                verify = Verify_(cipher_suite_choosen, &client_hello, server_hello, server_key_exchange->parameters, server_key_exchange->len_parameters, server_key_exchange->signature, len_signature, pubkey);
                
                FreeRecordLayer(server_message);
                FreeHandshake(server_handshake);
                
                OpenCommunication(server);
                break;
            case CERTIFICATE_REQUEST:
                certificate_request = HandshakeToCertificateRequest(server_handshake);
                
                SHA1_Update(&sha, server_message->message, sizeof(uint8_t)*(server_message->length-5));
                MD5_Update(&md5, server_message->message, sizeof(uint8_t)*(server_message->length-5));
                
                FreeRecordLayer(server_message);
                FreeHandshake(server_handshake);
                //FreeCertificateRequest(certificate_request);
                
                OpenCommunication(server);
                break;
            case SERVER_DONE:
                
                SHA1_Update(&sha,server_message->message, sizeof(uint8_t)*(server_message->length-5));
                MD5_Update(&md5,server_message->message, sizeof(uint8_t)*(server_message->length-5));
                
                FreeRecordLayer(server_message);
                FreeHandshake(server_handshake);
            
                phase = 3;
                break;
            default:
                perror("ERROR: Unattended message in phase 2.\n");
                exit(1);
                break;
        }
    
    }
    
    ///////////////////////////////////////////////////////////////PHASE 3//////////////////////////////////////////////////////////
    while(phase == 3){
        ///CERTIFICATE///

		///CLIENT_KEY_EXCHANGE///
        switch (cipher_suite_choosen->key_exchange_algorithm) {
            case RSA_:
                pre_master_secret_size = 48;
                pre_master_secret = (uint8_t*)calloc(pre_master_secret_size, sizeof(uint8_t));
                RAND_bytes(pre_master_secret, pre_master_secret_size);
                pre_master_secret[0] = std_version.major;
                pre_master_secret[1] = std_version.minor;
                pre_master_secret_encrypted = AsymEnc(pubkey, pre_master_secret, 48, &out_size);
                printf("%zu\n", out_size);
                
                client_key_exchange.parameters = pre_master_secret_encrypted;
                client_key_exchange.len_parameters = out_size;
                break;
            case DH_:
                client_key_exchange.len_parameters = DH_size(dh);
                client_key_exchange.parameters = calloc(client_key_exchange.len_parameters, sizeof(uint8_t));
                BN_bn2bin(dh->pub_key, client_key_exchange.parameters);
                
                pre_master_secret = (uint8_t*)calloc(DH_size(dh), sizeof(uint8_t));
                pre_master_secret_size = DH_compute_key(pre_master_secret, pub_key_server, dh);
                
                break;
            default:
                break;
        }
        
        handshake = ClientKeyExchangeToHandshake(&client_key_exchange, cipher_suite_choosen);
        record = HandshakeToRecordLayer(handshake);
        
        sendPacketByte(record);
        printRecordLayer(record);
        OpenCommunication(server);

        
        SHA1_Update(&sha,record->message, sizeof(uint8_t)*(record->length-5));
        MD5_Update(&md5,record->message, sizeof(uint8_t)*(record->length-5));
                
        FreeRecordLayer(record);
        FreeHandshake(handshake);

        //MASTER KEY COMPUTATION
        master_secret = MasterSecretGen(pre_master_secret, pre_master_secret_size, &client_hello, server_hello);
        
        //TODO: rimuovere questi print
        printf("MASTER KEY:generated\n");
        for (int i=0; i< 48; i++){
            printf("%02X ", master_secret[i]);
        }
        printf("\n\n");
        
        //KEYBLOCK GENERATION
        key_block = KeyBlockGen(master_secret, cipher_suite_choosen, &key_block_size, &client_hello, server_hello);
		
        printf("KEY BLOCK\n");
        for (int i=0; i< key_block_size; i++){
            printf("%02X ", key_block[i]);
        }
        printf("\n\n");
        
        ///CERTIFICATE_VERIFY///
        //OpenCommunication(server);        
        //while(CheckCommunication() == server){};
        phase = 4;
    }
    
    ///////////////////////////////////////////////////////////////PHASE 4//////////////////////////////////////////////////////////
    while(CheckCommunication() == server){};
    record = ChangeCipherSpecRecord();
    sendPacketByte(record);
    printRecordLayer(record);

    
    FreeRecordLayer(record);
    OpenCommunication(server);
    
    while(CheckCommunication() == server){};
    
    //building finished
    
    SHA1_Update(&sha, &sender, sizeof(uint32_t));
    MD5_Update(&md5, &sender, sizeof(uint32_t));
    
    SHA1_Update(&sha,master_secret,sizeof(uint8_t)*48);
    MD5_Update(&md5,master_secret,sizeof(uint8_t)*48);  
    
    SHA1_Update(&sha, pad_1, sizeof(uint8_t)*40);
    MD5_Update(&md5, pad_1, sizeof(uint8_t)*48);
    
    md5_1 = calloc(16, sizeof(uint8_t));
    sha_1 = calloc(20, sizeof(uint8_t));
    
    SHA1_Final(sha_1,&sha);
    MD5_Final(md5_1,&md5);
    
    SHA1_Init(&sha);
    MD5_Init(&md5);
    
    SHA1_Update(&sha, master_secret,sizeof(uint8_t)*48);
    SHA1_Update(&sha, pad_2,sizeof(uint8_t)*40);
    SHA1_Update(&sha, sha_1,sizeof(uint8_t)*20);
    
    MD5_Update(&md5, master_secret,sizeof(uint8_t)*48);
    MD5_Update(&md5, pad_2,sizeof(uint8_t)*48);
    MD5_Update(&md5, sha_1,sizeof(uint8_t)*16);
    
    md5_fin = calloc(16, sizeof(uint8_t));
    sha_fin = calloc(20, sizeof(uint8_t));
    
    SHA1_Final(sha_fin, &sha);
    MD5_Final(md5_fin, &md5);
    
    memcpy(finished.hash, md5_fin, 16*sizeof(uint8_t));
    memcpy(finished.hash + 16, sha_fin, 20*sizeof(uint8_t));
    
    /* MAC and ENCRYPTION*/
    
    
    handshake = FinishedToHandshake(&finished);   
    temp = HandshakeToRecordLayer(handshake);
    
    uint8_t length_bytes[4];
    int_To_Bytes(temp->length, length_bytes);
    printf("FINISHED:to sent\n");
    printf("%02X ", temp->type);
    printf("%02X ", temp->version.major);
    printf("%02X ", temp->version.minor);
    printf("%02X ", length_bytes[2]);
    printf("%02X ", length_bytes[3]);
    for(int i=0; i<temp->length - 5; i++){
        printf("%02X ", temp->message[i]);
    }
    printf("\n\n");
    
    //compute MAC
    
    for(int i=0;i<16; i++){
        client_write_MAC_secret[i]=key_block[i];
    }
    mac= MAC(cipher_suite_choosen,handshake,master_secret);

    //append MAC
    for(int i=0;i<sizeof(mac);i++){
        temp->message[temp->length - 5 + i]=mac[i];
    }
    
    // update length
    temp->length= temp->length + sizeof(mac);
                
    enc_message = DecEncryptPacket(temp->message, temp->length - 5, &enc_message_len, cipher_suite_choosen, key_block, client, 1);
    
    record2.type = HANDSHAKE;
    record2.length = enc_message_len + 5;
    record2.version = std_version;
    record2.message = enc_message;
        
    sendPacketByte(&record2);

    int_To_Bytes(record2.length, length_bytes);
    printf("ENCRYPED FINISHED: sent\n");
    printf("%02X ", record2.type);
    printf("%02X ", record2.version.major);
    printf("%02X ", record2.version.minor);
    printf("%02X ", length_bytes[2]);
    printf("%02X ", length_bytes[3]);
    for(int i=0; i<record2.length - 5; i++){
        printf("%02X ", record2.message[i]);
    }
    printf("\n\n");
    
	
    //FreeRecordLayer(record);
    //FreeHandshake(handshake);
    free(sha_1);
    free(md5_1);
    free(sha_fin);
    free(md5_fin);
    
    OpenCommunication(server);
    while(CheckCommunication() == server){};
    
    //CHANGE CIPHER SPEC
    server_message = readchannel();
    printRecordLayer(server_message);
    
    OpenCommunication(server);
    while(CheckCommunication() == server){};
    
    server_message = readchannel();
    
    int_To_Bytes(server_message->length, length_bytes);
    printf("FINISHED ENCRYPED: received\n");
    printf("%02X ", server_message->type);
    printf("%02X ", server_message->version.major);
    printf("%02X ", server_message->version.minor);
    printf("%02X ", length_bytes[2]);
    printf("%02X ", length_bytes[3]);
    for(int i=0; i<server_message->length - 5; i++){
        printf("%02X ", server_message->message[i]);
    }
    printf("\n\n");
    
    dec_message = DecEncryptPacket(server_message->message, server_message->length - 5, &dec_message_len, cipher_suite_choosen, key_block, server, 0);
    
    int_To_Bytes(dec_message_len + 5, length_bytes);
    printf("FINISHED DECRYPTED\n");
    printf("%02X ", server_message->type);
    printf("%02X ", server_message->version.major);
    printf("%02X ", server_message->version.minor);
    printf("%02X ", length_bytes[2]);
    printf("%02X ", length_bytes[3]);
    for(int i=0; i < dec_message_len; i++){
        printf("%02X ", dec_message[i]);
    }
    printf("\n\n");
    
    //FreeRecordLayer(server_message);
    //FreeHandshake(server_handshake);
    //FreeFinished(server_finished);
    free(master_secret);

    return 0;
    
}
