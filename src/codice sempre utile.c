if (ciphersuite_code < 0x17 || ciphersuite_code > 0x1B){
    switch (certificate_type) {
        case RSA_SIGN:
            
            break;
        case DSS_SIGN:
            break;
        case RSA_FIXED_DH:
            break;
        case DSS_FIXED_DH:
            break;
        case RSA_EPHEMERAL_DH:
            break;
        case DSS_EPHEMERAL_DH:
            break;
        case FORTEZZA_MISSI:
            break;
        default:
            perror("Certificate Type error.");
            exit(1);
            break;
    }



//RSA funzionamento base:



