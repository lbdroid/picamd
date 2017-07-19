CC = gcc
GIT_VERSION := $(shell git describe --abbrev=40 --dirty --always --tags)
LIBS = -lmicrohttpd -lsqlite3 -lpthread -lgps -lm

all: picamd

.PHONY: picamd.o
picamd.o: picamd.c
	$(CC) -DVERSION=\"$(GIT_VERSION)\" -g -c picamd.c

picamd: picamd.o
	$(CC) -g -o picamd picamd.o $(LIBS)

clean:
	rm -f picamd picamd.o
