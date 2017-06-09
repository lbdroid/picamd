CC = gcc
LIBS = -lmicrohttpd

all: picam

picam.o: picam.c
	$(CC) -g -c picam.c

picam: picam.o
	$(CC) -g -o picam picam.o $(LIBS)

clean:
	rm -f picam picam.o
