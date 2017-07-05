CC = gcc
LIBS = -lmicrohttpd -lsqlite3 -lpthread -lgps -lm

all: picamd

picamd.o: picamd.c
	$(CC) -g -c picamd.c

picamd: picamd.o
	$(CC) -g -o picamd picamd.o $(LIBS)

clean:
	rm -f picamd picamd.o
