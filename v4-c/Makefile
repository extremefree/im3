# Makefile — v4-c Linux (GCC)
CC      = gcc
CFLAGS  = -O2 -Wall -g
LDFLAGS = -no-pie

SRCS_SRV = server.c x25519.c crypto.c platform.c auth_v4.c utils.c
SRCS_CLI = client.c x25519.c crypto.c platform.c utils.c

all: server client

server: $(SRCS_SRV)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

client: $(SRCS_CLI)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f server client *.o

.PHONY: all clean
