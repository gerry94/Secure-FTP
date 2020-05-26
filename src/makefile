.POSIX:

CC=g++
CCFLAGS=-std=c++11
LDFLAGS=-lcrypto

.PHONY: all clean

all: client.cpp server.cpp
	$(CC) client.cpp hasher.cpp certmanager.cpp -o client $(LDFLAGS)
	$(CC) server.cpp hasher.cpp certmanager.cpp -o server $(LDFLAGS)
	#gnome-terminal -t server -- ./server
	make server_run

server_run:
	./server

clean:
	rm *.o
