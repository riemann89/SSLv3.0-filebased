CC := gcc
CFLAGS := -std=gnu99 -Wall -Iinclude -g
LFLAGS := -lssl -lcrypto -ldl
OPENSSL := -I/usr/local/ssl/include -L/usr/local/ssl/lib 

all: server client
	
server:SSL_utilities
	$(CC) $(CFLAGS) $(OPENSSL) src/Server.c build/* -o Server $(LFLAGS)

client: SSL_utilities
	$(CC) $(CFLAGS)  $(OPENSSL) src/Client.c build/* -o Client $(LFLAGS)

SSL_utilities:
	mkdir -p build
	$(CC) $(CFLAGS)  -I/usr/local/ssl/include -c src/structures.c -o build/structures.o 
	$(CC) $(CFLAGS)  -I/usr/local/ssl/include -c src/SSL_functions.c -o build/SSL_functions.o 
	$(CC) $(CFLAGS)  -I/usr/local/ssl/include -c src/Utilities.c -o build/Utilities.o

clean:
	rm -r build
	rm Client
	rm Server
	rm bancoprova
