CC := gcc
CFLAGS := -std=gnu99 -Wall -Iinclude
OPENSSL := -L/usr/local/ssl/lib -I/usr/local/ssl/include -lssl -lcrypto

all: server client
	
server:SSL_utilities
	$(CC) $(CFLAGS) src/Server.c build/* -o Server

client: SSL_utilities
	$(CC) $(CFLAGS) src/Client.c build/* -o Client 

SSL_utilities:
	mkdir -p build
	$(CC) $(CFLAGS)  -c src/SSL_functions.c build/structures.o -o build/SSL_functions.o 
	$(CC) $(CFLAGS)  -c src/structures.c -o build/structures.o 
	$(CC) $(CFLAGS)  -c src/Utilities.c -o build/Utilities.o

clean:
	rm -r build
	rm Client
	rm Server
