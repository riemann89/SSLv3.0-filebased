# SSLv3.0
C implementation of SSL3.0 protocol - File Based

tested on OpenSSL 1.0.2 22 Jan 2015
https://www.openssl.org/source/old/1.0.2/openssl-1.0.2.tar.gz

Leak were fixed using valgrind

to compile the source code is sufficient to launch the make file

How to use the program:
Launch simoultaneously Client and Server.
In the console of Client will be asked which ciphersuite you want to use, inserd the corresponding code in Hex format as specified on rfc, for example 0x06.
The Ciphers supported go from 0x03 to 0x0A and from 0x11 to 0x16.
On both the consoles will be printed all the messages read and sent and what it's doing, it should be easy to understand what the two programs are doing.
