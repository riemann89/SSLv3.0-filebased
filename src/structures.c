//
//  structures.c
//  SSLv3.0
//
//  Created by Giuseppe Giffone on 17/02/16.
//  Copyright © 2016 Giuseppe Giffone. All rights reserved.
//

#include "structures.h"

Cipher_Suite lista[31]={
    {0x00,"SSL_NULL_WITH_NULL_NULL"},
    {0x01,"SSL_RSA_WITH_NULL_MD5"},
    {0x02,"SSL_RSA_WITH_NULL_SHA"},
    {0x03,"SSL_RSA_EXPORT_WITH_RC4_40_MD5"},
    {0x04,"SSL_RSA_WITH_RC4_128_MD5"},
    {0x05,"SSL_RSA_WITH_RC4_128_SHA"},
    {0x06,"SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
    {0x07,"SSL_RSA_WITH_IDEA_CBC_SHA"},
    {0x08,"SSL_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x09,"SSL_RSA_WITH_DES_CBC_SHA"},
    {0x0A,"SSL_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x0B,"SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0C,"SSL_DH_DSS_WITH_DES_CBC_SHA"},
    {0x0D,"SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0x0E,"SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0F,"SSL_DH_RSA_WITH_DES_CBC_SHA"},
    {0x10,"SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x11,"SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"},
    {0x12,"SSL_DHE_DSS_WITH_DES_CBC_SHA"},
    {0x13,"SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0x14,"SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x15,"SSL_DHE_RSA_WITH_DES_CBC_SHA"},
    {0x16,"SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x17,"SSL_DH_anon_EXPORT_WITH_RC4_40_MD5"},
    {0x18,"SSL_DH_anon_WITH_RC4_128_MD5"},
    {0x19,"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"},
    {0x1A,"SSL_DH_anon_WITH_DES_CBC_SHA"},
    {0x1B,"SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"},
    {0x1C,"SSL_FORTEZZA_KEA_WITH_NULL_SHA"},
    {0x1D,"SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"},
    {0x1E,"SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"}
};

ProtocolVersion std_version={0,3};

Cipher_Suite get_cipher_suite(uint8_t id){
	for(int i=0;i<31;i++)
		if(lista[i].code == id)
			return lista[i];
	printf("\nError id not valid\n");
	exit(1);
}

