.POSIX:

CC=g++
CCFLAGS=-std=c++11
LDFLAGS=-lcrypto

.PHONY: all clean

all: client.cpp server.cpp
	$(CC) client.cpp hasher.cpp certmanager.cpp -o client $(LDFLAGS)
	$(CC) server.cpp hasher.cpp certmanager.cpp -o server $(LDFLAGS)
	gnome-terminal -t server -- ./server #apro nuovo terminale e lancio il server
	make client_run

client_run:
	./client

clean:
	rm *.o
