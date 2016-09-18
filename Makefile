CC := gcc
CFLAGS := -std=gnu99 -Wall -Iinclude -g
OPENSSL := -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto -ldl

all: server client banco
	
server:SSL_utilities
	$(CC) $(CFLAGS)  src/Server.c build/* -o Server $(OPENSSL)

client: SSL_utilities
	$(CC) $(CFLAGS)  src/Client.c build/* -o Client $(OPENSSL)

banco: SSL_utilities
	$(CC) $(CFLAGS)  src/bancoprova.c build/* -o bancoprova $(OPENSSL)

SSL_utilities:
	mkdir -p build
	$(CC) $(CFLAGS)  -c src/structures.c -o build/structures.o $(OPENSSL)
	$(CC) $(CFLAGS)  -c src/SSL_functions.c build/structures.o -o build/SSL_functions.o $(OPENSSL)
	$(CC) $(CFLAGS)  -c src/Utilities.c -o build/Utilities.o $(OPENSSL)

clean:
	rm -r build
	rm Client
	rm Server
	rm bancoprova
