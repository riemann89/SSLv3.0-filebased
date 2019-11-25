#include "crypto_binding.h"

/**
 * BaseFunction that computes number_of_MD5 MD5 hash of the principal argument concatenated with random of Client and Server Hello
 * @param int numer_of_MD5
 * @param uint8_t *principal_argument
 * @param int principal_argument_size
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @return uint8_t *buffer
 */
uint8_t *BaseFunction(int numer_of_MD5, uint8_t* principal_argument, int principal_argument_size, ClientServerHello *client_hello, ClientServerHello *server_hello){
    
    uint8_t *buffer;
    uint8_t letter;
    MD5_CTX md5;
    SHA_CTX sha;
    uint8_t *md5_1, *sha_1;
    
    buffer=NULL;
    letter=0;
    md5_1=NULL;
    sha_1=NULL;
    
    letter = 65;
    buffer = calloc(16*numer_of_MD5, sizeof(uint8_t));
    
    if (buffer == NULL){
        perror("ERROR base_function: memory allocation leak.");
        exit(1);
    }
    
    sha_1 = calloc(20, sizeof(uint8_t));
    
    if (sha_1 == NULL){
        perror("ERROR base_function: memory allocation leak.");
        exit(1);
    }
    
    md5_1 = calloc(16, sizeof(uint8_t));
    
    if (md5_1 == NULL){
        perror("ERROR base_function: memory allocation leak.");
        exit(1);
    }
    
    for(int i = 0; i < numer_of_MD5 ; i++){
        SHA1_Init(&sha);
        letter = letter + i;
        
        for (int j = 0; j < i + 1; j++) {
            SHA_Update(&sha, &letter, sizeof(uint8_t));
        }
        
        SHA1_Update(&sha, principal_argument, principal_argument_size*sizeof(uint8_t));
        SHA1_Update(&sha, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        SHA1_Update(&sha, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        SHA1_Update(&sha, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        SHA1_Update(&sha, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        
        SHA1_Final(sha_1, &sha);
        
        MD5_Init(&md5);
        MD5_Update(&md5, principal_argument, principal_argument_size*sizeof(uint8_t));
        MD5_Update(&md5, sha_1, 20*sizeof(uint8_t));
        MD5_Final(md5_1, &md5);
        
        memcpy(buffer + 16*i, md5_1, 16*sizeof(uint8_t));
    }
    free(md5_1);
    free(sha_1);
    return buffer;
    
}

/*************************************** CERTIFICATES ******************************************************/

/**
 * extract the public key read from the certificate
 * @param Certificate *certificate
 * @return EVP_KEY *pubkey
 */
EVP_PKEY* readCertificateParam (Certificate *certificate){
    
    X509 *cert_509;
    EVP_PKEY *pubkey;
    const unsigned char *p;
    int len;
    
    cert_509 = NULL;
    pubkey=NULL;
    len=0;
    
    p = certificate->X509_der;
    len = certificate->len;
    cert_509 = d2i_X509(NULL, &p, len);
    
    if(cert_509 == NULL){
        perror("readCertificateParam Error: memory allocation leak.");
        exit(1);
    }
    pubkey = X509_get_pubkey(cert_509);
    X509_free(cert_509);
    
    return pubkey;
}
/*************************************** KEYS GENERATION ******************************************************/
/**
 * derives the master_secret from pre_master_secret, client hello and server hello
 * @param uint8_t *pre_master_secret
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @return uint8_t *master_secret
 */
uint8_t *MasterSecretGen(uint8_t *pre_master_secret, int pre_master_len, ClientServerHello *client_hello, ClientServerHello *server_hello){
    
    uint8_t *master_secret;
    master_secret=NULL;
    
    master_secret = BaseFunction(3, pre_master_secret, pre_master_len, client_hello, server_hello);
    
    if (master_secret == NULL) {
        perror("MasterSecretGen Error: memory leak.");
        exit(1);
    }
    
    return master_secret;
}
/**
 * Generate key_block
 * @param uint8_t *master_secret
 * @param CipherSuite *cipher_suite
 * @param int *size
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @return uint8_t *key_block
 */
uint8_t *KeyBlockGen(uint8_t *master_secret, CipherSuite *cipher_suite, int *size, ClientServerHello *client_hello, ClientServerHello *server_hello){
    
    uint8_t *key_block, *key_block_temp, *final_client_write_key, *final_server_write_key, *client_write_iv, *server_write_iv;
    MD5_CTX md5;
    int key_block_size, key_block_size_temp;
    
    key_block = NULL;
    key_block_temp = NULL;
    final_client_write_key = NULL;
    final_server_write_key = NULL;
    client_write_iv=NULL;
    server_write_iv=NULL;
    key_block_size = 0;
    key_block_size_temp = 0;
    
    if (cipher_suite->exportable == false) {
        key_block_size = 2*(cipher_suite->hash_size + cipher_suite->key_material + cipher_suite->iv_size);
        key_block_size = key_block_size + (16 - (key_block_size % 16)); //made a multiple of 16
        key_block = BaseFunction(key_block_size/16, master_secret, 48, client_hello, server_hello);
        *size = key_block_size;
    }
    else{
        //KeyBlock temp
        key_block_size_temp = 2*(cipher_suite->hash_size + cipher_suite->key_material);
        key_block_size_temp = key_block_size_temp + (16 - (key_block_size_temp % 16)); //made a multiple of 16
        key_block_temp = BaseFunction(key_block_size_temp/16, master_secret, 48, client_hello, server_hello);
        
        //final write key
        //client
        final_client_write_key = calloc(16, sizeof(uint8_t));
        
    	MD5_Init(&md5);
        MD5_Update(&md5, key_block_temp + 2*(cipher_suite->hash_size), cipher_suite->key_material);
        MD5_Update(&md5, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Update(&md5, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Final(final_client_write_key, &md5);
        
        //server
        final_server_write_key = calloc(16, sizeof(uint8_t));
        
        MD5_Init(&md5);
        MD5_Update(&md5, key_block_temp + 2*(cipher_suite->hash_size) + cipher_suite->key_material, cipher_suite->key_material);
        MD5_Update(&md5, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Update(&md5, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Final(final_server_write_key, &md5);
        
        //iv bytes
        client_write_iv = calloc(16, sizeof(uint8_t));
        
        MD5_Init(&md5);
        MD5_Update(&md5, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Update(&md5, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Final(client_write_iv, &md5);
        
        //server
        server_write_iv = calloc(16, sizeof(uint8_t));
        
        MD5_Init(&md5);
        MD5_Update(&md5, &server_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, server_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Update(&md5, &client_hello->random->gmt_unix_time, sizeof(uint32_t));
        MD5_Update(&md5, client_hello->random->random_bytes, 28*sizeof(uint8_t));
        MD5_Final(server_write_iv, &md5);
        
        //construct final keyblock
        *size = 2*cipher_suite->hash_size + 64;
        key_block =(uint8_t*)realloc(key_block_temp, (*size)*sizeof(uint8_t));
        memcpy(key_block + 2*(cipher_suite->hash_size), final_client_write_key, 16);
        memcpy(key_block + 2*(cipher_suite->hash_size) + 16, final_server_write_key, 16);
        memcpy(key_block + 2*(cipher_suite->hash_size) + 32, client_write_iv, 16);
        memcpy(key_block + 2*(cipher_suite->hash_size) + 48, server_write_iv, 16);
        
        free(final_client_write_key);
        free(final_server_write_key);
        free(client_write_iv);
        free(server_write_iv);  
    }   
    return key_block;    
}

/**
 * Initialize a DH struct containing a prime p and a group generator g.
 * @return uint8_t *dh
 */

DH *get_dh2048(){
    
    DH *dh;
    
    dh=NULL;
    
    static unsigned char dh2048_p[]={
        0xC5,0x36,0x72,0xCF,0x5A,0xA4,0x02,0xDA,0x0B,0xD2,0x49,0xE9,
        0x86,0x33,0xDF,0x51,0x06,0xE1,0x93,0x9E,0xDD,0x95,0xEA,0x5E,
        0x9A,0x80,0x47,0x3F,0x7D,0x4F,0x5D,0x19,0x09,0x9B,0xEA,0x6E,
        0x3B,0x89,0xD7,0xB8,0xC5,0xD5,0x28,0x57,0x4A,0xAA,0xEF,0x21,
        0x72,0x18,0x12,0x80,0xD5,0x15,0xEE,0x8C,0x9A,0x04,0xB0,0x23,
        0x89,0x98,0x62,0x5D,0xC8,0xA1,0x84,0x5E,0x1C,0x70,0x01,0xE1,
        0x1A,0x75,0x45,0xF0,0x90,0x7D,0x84,0x53,0x10,0xD5,0x65,0x98,
        0xF9,0x2E,0x7A,0xC4,0x5C,0xAF,0x76,0xB9,0x83,0xB3,0xF6,0x14,
        0x61,0x83,0xD8,0xCA,0x31,0x94,0xF4,0xF9,0x0B,0x6C,0x37,0x11,
        0x42,0xE7,0x16,0x50,0x76,0x24,0xE9,0x48,0x3E,0x19,0xFF,0x6E,
        0xEF,0x98,0x10,0x09,0x98,0x93,0x2E,0xAB,0x23,0xB5,0x9D,0xBB,
        0xB9,0x69,0xFD,0x6E,0xD1,0x85,0xA8,0xEF,0x8B,0x51,0xE7,0x0A,
        0x45,0x32,0x82,0x3B,0xD4,0x71,0x0C,0x8A,0x7A,0x79,0xF3,0x08,
        0x6C,0xBE,0xE3,0x61,0x11,0x40,0xF1,0x98,0x4E,0xF4,0x7B,0xD6,
        0xF5,0x6C,0xD5,0xCF,0x7B,0xF6,0xA2,0xBF,0xB8,0xAD,0xF2,0x29,
        0x3D,0x4E,0xDE,0x9A,0xEB,0xF5,0x8C,0x2E,0xEA,0x0D,0x0A,0x24,
        0xB3,0x82,0x84,0xEC,0x21,0xD2,0x87,0x8A,0xD2,0x12,0x12,0xA3,
        0x4F,0xC8,0xC0,0x09,0xDD,0x09,0x41,0xD2,0xEB,0x93,0xCE,0x94,
        0xBA,0xA2,0x5A,0x17,0x98,0x8A,0xB3,0x1C,0x13,0x6C,0xD8,0x7C,
        0x12,0x6E,0x57,0x0B,0x74,0xAC,0xF5,0xB6,0x22,0xBC,0xD4,0xC6,
        0x3C,0xC2,0x90,0x08,0xB8,0x9E,0x61,0x85,0xE8,0x3B,0x15,0x1B,
        0x2A,0x52,0x01,0xE3,
    };
    static unsigned char dh2048_g[]={
        0x02,
    };
   
    if ((dh=DH_new()) == NULL){
        return(NULL);
    }
    dh->p = BN_bin2bn(dh2048_p, sizeof(dh2048_p),NULL);
    dh->g = BN_bin2bn(dh2048_g, sizeof(dh2048_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL)){
        DH_free(dh);
        return(NULL);
    }
    return(dh);
}


/*************************************** ENCRYPTION ******************************************************/
//Asymmetric

/**
 * encrypts plaintext using public_key
 * @param EVP_KEY *pKey
 * @param uint8_t *plaintext
 * @param size_t inlen
 * @param size_t *outlen
 * @return uint8_t *ciphertext
 */
uint8_t* AsymEnc(EVP_PKEY *public_key, uint8_t* plaintext, size_t inlen, size_t *outlen){
   
    EVP_PKEY_CTX *ctx;
    uint8_t *ciphertext;
    
    ctx = NULL;
    ciphertext = NULL;
    
    ctx = EVP_PKEY_CTX_new(public_key, NULL);
    
    if (!ctx){
        exit(1);}
    /* Error occurred */
    if (EVP_PKEY_encrypt_init(ctx) <= 0){
            exit(1);}
    /* Error */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){
        perror("Asymmetric Encryption error - setting rsa key.");
        exit(1);
    }
    /* Error */
                
    /* Determine buffer length */
    if (EVP_PKEY_encrypt(ctx, NULL, outlen, plaintext, inlen) <= 0){
        exit(1);}
    /* Error */
    
    //ciphertext = OPENSSL_malloc(outlen);
    ciphertext = (uint8_t*)calloc(*outlen, sizeof(uint8_t));
    
    /* malloc failure */
    if (!ciphertext){
        perror("Asymmetric Encryption error - memory allocation leak.");
        exit(1);
    }
	
    /*Encryption Error */
    if (EVP_PKEY_encrypt(ctx, ciphertext, outlen, plaintext, inlen) <= 0){
        perror("Asymmetric Encryption error - encryption leak.");
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx);
    return ciphertext;
}

/**
 * decrypt ciphertext using private_key
 * @param KeyExchangeAlgorithm alg
 * @param uint8_t *ciphertext
 * @param size_t inlen
 * @param int *out_size
 * @return uint8_t *plaintext
 
 */
uint8_t* AsymDec(int private_key_type, uint8_t *ciphertext, size_t inlen, size_t *outlen, EVP_PKEY *private_key){

    uint8_t *plaintext;
    EVP_PKEY_CTX *ctx;
    
    plaintext = NULL;
    ctx = NULL;
    
    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx){
        exit(1);
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0){
        perror("Asymmetric Decryption error - ctx init not performed.");
        exit(1);
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){
        perror("Asymmetric Decryption error - setting rsa key.");
        exit(1);
    }
	
    if (EVP_PKEY_decrypt(ctx, NULL, outlen, plaintext, inlen) <= 0){
        perror("Asymmetric Decryption error - encryption leak.");
        exit(1);
    }
                    
    plaintext = (uint8_t*)calloc(*outlen, sizeof(uint8_t));
    
    if (!plaintext){
        perror("Asymmetric Decryption error - allocation meamory leak.");
        exit(1);
    }
        
    if (EVP_PKEY_decrypt(ctx, plaintext, outlen, ciphertext, inlen) <= 0){
        perror("Asymmetric Decryption error - decryption leak.");
        exit(1);
    }
	
    EVP_PKEY_CTX_free(ctx);   
    return plaintext;
}

/**
 * decrypt an enciphred packet 
 * @param uint8_t *in_packet
 * @param int in_packet_len
 * @param int *out_packet_len
 * @param CipherSuite *cipher_suite
 * @param uint8_t *key_block
 * @param Talker key_talker
 * @param int state
 * @return uint8_t *out_packet
 */
uint8_t* DecEncryptPacket(uint8_t *in_packet, int in_packet_len, int *out_packet_len, CipherSuite *cipher_suite, uint8_t* key_block, Talker key_talker, int state){
    
    uint8_t *out_packet;
    EVP_CIPHER_CTX ctx;
    uint8_t *key, *iv;
    uint8_t shift1, shift2;
    
    
    shift1 = 0;
    shift2 = 0;
    key = NULL;
    iv = NULL;
    out_packet = NULL;
    
    EVP_CIPHER_CTX_init(&ctx);
    if (cipher_suite->exportable) {
        if (key_talker == server) {
            shift1 = 16;
            shift2 = 16;
        }
        key = key_block + (2*cipher_suite->hash_size + shift1);
        iv = key + 32;
        
    }
    else{
        if (key_talker == server) {
            shift1 = cipher_suite->key_material;
            shift2 = cipher_suite->iv_size;
        }
        key = key_block + (2*cipher_suite->hash_size + shift1);
        iv = key_block + (2*cipher_suite->hash_size + 2*cipher_suite->key_material + shift2);
    }

    switch (cipher_suite->cipher_algorithm) {
        case RC4:
            switch (cipher_suite->key_material) {
                case 5:
                    EVP_CipherInit_ex(&ctx, EVP_rc4(), NULL, key, iv, state);
                    EVP_CIPHER_CTX_set_key_length(&ctx, 40);
                    break;
                case 16:
                    //beta
                    EVP_CipherInit_ex(&ctx, EVP_rc4(), NULL, key, iv, state);
                    break;
                    
                default:
                    perror("DecEncryptPacket error: RC4 size not corrected.\n");
                    exit(1);
                    break;
            }
            break;
            
        case RC2:
            EVP_CipherInit_ex(&ctx, EVP_rc2_40_cbc(), NULL, key, iv, state);
            break;
        
        case IDEA:
            EVP_CipherInit_ex(&ctx, EVP_idea_cbc(), NULL, key, iv, state);
            break;
        
        case DES40:
            EVP_CipherInit_ex(&ctx, EVP_des_cbc(), NULL, NULL, NULL, state);
            EVP_CIPHER_CTX_set_key_length(&ctx, 40);
            EVP_CipherInit_ex(&ctx, EVP_des_cbc(), NULL, key, iv, state);
            
            break;
        
        case DES:
            EVP_CipherInit_ex(&ctx, EVP_des_cbc(), NULL, key, iv, state);
            break;
        
        case DES3:
            EVP_CipherInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, key, iv, state);
            break;
        
        default:
            perror("DecEncryptPacket error: unknown cipher algorithm.");
            exit(1);
            break;
    }
    int tmp_len;
    
    out_packet = calloc(64, sizeof(uint8_t));
    
    EVP_CipherUpdate(&ctx, out_packet, out_packet_len, in_packet, in_packet_len);
    EVP_CipherFinal_ex(&ctx, out_packet + *out_packet_len, &tmp_len);
    *out_packet_len += tmp_len;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return out_packet;  
}

/**
 * MAC of the Handshake hand.
 * could be made using sha1 or md5 according to the CipherSuite cipher in input
 * @param CipherSuite cipher
 * @param Handshake *hand
 * @param uint8_t *macWriteSecret
 * @return uint8_t *sha_fin or *md5_fin
 */
uint8_t* MAC(CipherSuite *cipher, Handshake *hand, uint8_t *macWriteSecret){
    MD5_CTX md5, md52;
    SHA_CTX sha, sha2;
    uint64_t seq_num;
    uint32_t len;
    uint8_t *sha_fin,*md5_fin;
    
    sha_fin=NULL;
    md5_fin=NULL;
    seq_num=1;
    len= hand->length - 4;
    
    if(cipher->hash_algorithm == SHA1_){
        
        SHA1_Init(&sha);
        SHA1_Init(&sha2);
        
        sha_fin = calloc(20, sizeof(uint8_t));
        
        SHA1_Update(&sha, macWriteSecret, 16*sizeof(uint8_t));
        SHA1_Update(&sha,pad_1, sizeof(pad_1));
        SHA1_Update(&sha, &seq_num, sizeof(uint64_t));
        SHA1_Update(&sha, &hand->msg_type , sizeof(uint8_t));
        SHA1_Update(&sha, &len, sizeof(uint32_t));
        SHA1_Update(&sha, hand->content, (hand->length - 4)*sizeof(uint8_t));
        SHA1_Final(sha_fin,&sha);
        
        SHA1_Update(&sha2,macWriteSecret, 16*sizeof(uint8_t));
        SHA1_Update(&sha2,pad_2, sizeof(pad_2));
        SHA1_Update(&sha2, sha_fin,20*sizeof(uint8_t));
        
        SHA1_Final(sha_fin,&sha2);
            
        return sha_fin;      
    }
    else if(cipher->hash_algorithm == MD5_1){
        
        MD5_Init(&md5);
        MD5_Init(&md5);
    
        md5_fin = calloc(16, sizeof(uint8_t));
               
        MD5_Init(&md5);
        MD5_Init(&md52);
        MD5_Update(&md5, macWriteSecret, 16*sizeof(uint8_t));
        MD5_Update(&md5,pad_1, sizeof(pad_1));
        MD5_Update(&md5, &seq_num, sizeof(uint64_t));
        MD5_Update(&md5, &hand->msg_type ,sizeof(uint8_t));
        MD5_Update(&md5, &len, sizeof(uint32_t));
        MD5_Update(&md5,hand->content, (hand->length - 4)*sizeof(uint8_t));
        MD5_Final(md5_fin,&md5);
        
        MD5_Update(&md52,macWriteSecret, 16*sizeof(uint8_t));
        MD5_Update(&md52,pad_2, sizeof(pad_2));
        MD5_Update(&md52, md5_fin, 16*sizeof(uint8_t));
        
        MD5_Final(md5_fin, &md52);
            
        return md5_fin;
    }
    else{
        perror("MAC Error: signature algorithm not valid.");
        exit(1);
    }
}

/**
 * compute the SSL signature of params array of size len_params by private key pKey
 * @param CipherSuite *cipher
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @param uint8_t *params
 * @param int *len_params
 * @param EVP_PKEY *pKey
 * @return uint8_t *signature
 */
uint8_t* Signature_(CipherSuite *cipher, ClientServerHello *client_hello, ClientServerHello *server_hello, uint8_t* params, int len_params, EVP_PKEY *pKey, unsigned int *slen){
    
    EVP_MD_CTX *mdctx;
    uint8_t *signature;
    uint8_t *data;
    uint8_t temp[4];
    
    signature = NULL;
    data = NULL;
    mdctx = NULL;
    
    mdctx = EVP_MD_CTX_create();
    
    //hash
    data = (uint8_t*)calloc(62 + len_params, sizeof(uint8_t));
    
    int_To_Bytes(client_hello->random->gmt_unix_time, temp);
    data[0] = temp[1];
    data[1] = temp[2];
    data[2] = temp[3];
    
    for (int i = 0; i<28; i++) {
        data[i+3] = client_hello->random->random_bytes[i];
    }
    
    int_To_Bytes(server_hello->random->gmt_unix_time, temp);
    data[31] = temp[1];
    data[32] = temp[2];
    data[33] = temp[3];
    
    for (int i = 0; i<28; i++){
        data[i+34] = server_hello->random->random_bytes[i];
    	}
    
    for (int i = 0; i<len_params; i++){
        data[62 + i] = params[i];
    	}
    

    switch (cipher->signature_algorithm){
        
        case RSA_s:
            EVP_SignInit_ex(mdctx, EVP_md5(), NULL);
            EVP_SignUpdate(mdctx, data, 62 + len_params);
            
            EVP_SignInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_SignUpdate(mdctx, data, 62 + len_params);
            break;
        
        case DSA_s:
            EVP_SignInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_SignUpdate(mdctx, data, 62 + len_params);
            
            break;
        
        default:
            perror("key exchange algorithm not supported");
            exit(1);
            break;
               
    }
    EVP_SignFinal(mdctx, NULL, slen, pKey);
    signature = (uint8_t*)calloc(*slen, sizeof(uint8_t));
    EVP_SignFinal(mdctx, signature, slen, pKey);
    printf("slen%d\n", *slen);
    free(data);
    EVP_MD_CTX_destroy(mdctx);
    
    return signature;
}

/**
 * verify the SSL signature of params array of size len_params by certificate
 * @param CipherSuite *cipher
 * @param ClientServerHello *client_hello
 * @param ClientServerHello *server_hello
 * @param uint8_t *params
 * @param int *len_params
 * @param uin8_t *signature
 * @param int *len_signature
 * @param Certificate *certificate
 * @return uint8_t *signature
 */
void Verify_(CipherSuite *cipher, ClientServerHello *client_hello, ClientServerHello *server_hello, uint8_t* params, int len_params, uint8_t *signature, int len_signature, Certificate *certificate){
    
    EVP_MD_CTX *mdctx;
    uint8_t *data;
    uint8_t temp[4];
    EVP_PKEY *pubKey;
    
    data = NULL;
    mdctx=NULL;
    pubKey=NULL;
    
    mdctx = EVP_MD_CTX_create();
    pubKey = readCertificateParam(certificate);
    
    //hash
    data = (uint8_t*)calloc(62 + len_params, sizeof(uint8_t));
    
    int_To_Bytes(client_hello->random->gmt_unix_time, temp);
    data[0] = temp[1];
    data[1] = temp[2];
    data[2] = temp[3];
    
    for (int i = 0; i<28; i++) {
        data[i+3] = client_hello->random->random_bytes[i];
    }
    
    int_To_Bytes(server_hello->random->gmt_unix_time, temp);
    data[31] = temp[1];
    data[32] = temp[2];
    data[33] = temp[3];
    
    for (int i = 0; i<28; i++) {
        data[i+34] = server_hello->random->random_bytes[i];
    }
    
    for (int i = 0; i<len_params; i++) {
        data[62 + i] = params[i];
    }
        
    switch (cipher->signature_algorithm){
            
        case RSA_s:
            EVP_VerifyInit_ex(mdctx, EVP_md5(), NULL);
            EVP_VerifyUpdate(mdctx, data, 62 + len_params);
            
            EVP_VerifyInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_VerifyUpdate(mdctx, data, 62 + len_params);
            break;
            
        case DSA_s:
            EVP_VerifyInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_VerifyUpdate(mdctx, data, 62 + len_params);
            break;
            
        default:
            perror("key exchange algorithm not supported");
            exit(1);
            break;
            
    }
    
    if(EVP_VerifyFinal(mdctx, signature, len_signature, pubKey) == 1){
        printf("Signature correct.\n");
    }
    else{
        perror("Signature non corretta");
        exit(1);
    }
    
    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_destroy(mdctx);
    free(data);
}