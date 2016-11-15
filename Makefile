CC := gcc
CFLAGS := -std=gnu99 -Wall -Iinclude -g
LFLAGS := -lssl -lcrypto -ldl
OPENSSL := -I/usr/local/ssl/include -L/home/ermes/Downloads/openssl-1.0.2

all: server client
	
server:SSL_utilities
	$(CC) $(CFLAGS) $(OPENSSL) src/Server.c build/* -o Server $(LFLAGS)

client: SSL_utilities
	$(CC) $(CFLAGS)  $(OPENSSL) src/Client.c build/* -o Client $(LFLAGS)

SSL_utilities:
	mkdir -p build
	$(CC) $(CFLAGS)  $(OPENSSL) -c src/structures.c -o build/structures.o $(LFLAGS)
	$(CC) $(CFLAGS)  $(OPENSSL) -c src/SSL_functions.c -o build/SSL_functions.o $(LFLAGS)
	$(CC) $(CFLAGS)  $(OPENSSL) -c src/Utilities.c -o build/Utilities.o $(LFLAGS)

clean:
	rm -r build
	rm Client
	rm Server
	rm bancoprova
