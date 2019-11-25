CC := gcc
CFLAGS := -std=gnu99 -Wall -Iinclude -g
LFLAGS := -lssl -lcrypto -ldl
OPENSSL := -I/usr/local/ssl/include -L/usr/local/ssl/lib 

all: server client
	
server:SSL_utilities
	$(CC) $(CFLAGS) $(OPENSSL) src/server/server.c build/* -o Server $(LFLAGS)

client: SSL_utilities
	$(CC) $(CFLAGS)  $(OPENSSL) src/client/client.c build/* -o Client $(LFLAGS)

SSL_utilities:
	mkdir -p build
	$(CC) $(CFLAGS)  -I/usr/local/ssl/include -c src/utilities/structures.c -o build/structures.o
	$(CC) $(CFLAGS)  -I/usr/local/ssl/include -c src/utilities/networking.c -o build/networking.o
	$(CC) $(CFLAGS)  -I/usr/local/ssl/include -c src/utilities/crypto_binding.c -o build/crypto_binding.o
	$(CC) $(CFLAGS)  -I/usr/local/ssl/include -c src/utilities/SSL_functions.c -o build/SSL_functions.o 
	$(CC) $(CFLAGS)  -I/usr/local/ssl/include -c src/utilities/utilities.c -o build/utilities.o

clean:
	rm -r build
	rm client
	rm server
	rm -r client.dSYM
	rm -r server.dSYM

