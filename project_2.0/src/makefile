.POSIX:

CC=g++
CCFLAGS=-std=c++11
LDFLAGS=-lcrypto

.PHONY: all clean

all: client.cpp server.cpp
	$(CC) -o client client.cpp $(LDFLAGS)
	$(CC) -o server server.cpp $(LDFLAGS)
	gnome-terminal -t server -- ./server #apro nuovo terminale e lancio il server
	make client_run

client_run:
	./client

clean:
	rm *.o
