# Makefile — v4 Linux (ELF64)
# On Windows use: mingw32-make -f Makefile.win
ifeq ($(OS),Windows_NT)
  $(error On Windows, run: mingw32-make -f Makefile.win)
endif
CC      = gcc
NASM    = nasm
NASMFLAGS = -f elf64
CFLAGS  = -O2 -Wall -g
LDFLAGS = -no-pie

ASM_SRCS = crypto.asm net_utils.asm server_main.asm client_main.asm
ASM_OBJS = $(ASM_SRCS:.asm=.o)

C_SRCS  = platform.c auth_v4.c x25519_impl.c
C_OBJS  = $(C_SRCS:.c=.o)

# net_utils.asm 里有 util_* 函数，buffer.asm 也需要
EXTRA_ASM = buffer.asm
EXTRA_OBJ = $(EXTRA_ASM:.asm=.o)

all: server client

server: server_main.o x25519_impl.o crypto.o buffer.o net_utils.o platform.o auth_v4.o
	$(CC) $(LDFLAGS) -o server $^ -lm

client: client_main.o x25519_impl.o crypto.o net_utils.o platform.o
	$(CC) $(LDFLAGS) -o client $^

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o server client

.PHONY: all clean
