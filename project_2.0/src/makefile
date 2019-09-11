.POSIX:

CC=g++
CCFLAGS=-std=c++11
LDFLAGS=-lcrypto

.PHONY: all clean

all: client.cpp server.cpp
	$(CC) -o client client.cpp -lcrypto
	$(CC) -o server server.cpp -lcrypto
	gnome-terminal -t server -e ./server #apro nuovo terminale e lancio il server
	make client_target

client_target:
	./client

clean:
	rm *.o
