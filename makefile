CC=gcc
CFLAGS=-g -w

all: server client

server: server.c
	$(CC) $(CFLAGS) -o server server.c -lcjson

client: client.c
	$(CC) $(CFLAGS) -o client client.c -lssl -lcrypto -lcjson

clean:
	rm -f server client