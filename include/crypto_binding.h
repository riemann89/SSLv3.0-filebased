#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/md5.h>

#include "structures.h"
#include "utilities.h"
#include "openssl/x509.h"
#include "openssl/pem.h"

/* CERTIFICATE */
Certificate* loadCertificate(char * cert_name);
EVP_PKEY* readCertificateParam (Certificate *certificate);
DH *get_dh2048();

/* KEY BLOCK*/
uint8_t *BaseFunction(int numer_of_MD5, uint8_t* principal_argument, int principal_argument_size, ClientServerHello *client_hello, ClientServerHello *server_hello);
uint8_t *MasterSecretGen(uint8_t *pre_master_secret, int pre_master_len, ClientServerHello *client_hello, ClientServerHello *server_hello);
uint8_t *KeyBlockGen(uint8_t *master_secret, CipherSuite *cipher_suite, int *size, ClientServerHello *client_hello, ClientServerHello *server_hello);

//encryption
//asymmetric
uint8_t* AsymEnc(EVP_PKEY *public_key, uint8_t* plaintext, size_t inlen, size_t *outlen);
uint8_t* AsymDec(int private_key_type, uint8_t *ciphertext, size_t inlen, size_t *outlen, EVP_PKEY *private_key);

//symmetric
uint8_t* DecEncryptPacket(uint8_t *in_packet, int in_packet_len, int *out_packet_len, CipherSuite *cipher_suite, uint8_t* key_block, Talker key_talker, int state);

//authentication
uint8_t* MAC(CipherSuite *cipher, Handshake *hand, uint8_t* macWriteSecret);
uint8_t* Signature_(CipherSuite *cipher, ClientServerHello *client_hello, ClientServerHello *server_hello, uint8_t* params, int len_params, EVP_PKEY *pKey, unsigned int *slen);
void Verify_(CipherSuite *cipher, ClientServerHello *client_hello, ClientServerHello *server_hello, uint8_t* params, int len_params, uint8_t *signature, int len_signature, Certificate *certificate);
