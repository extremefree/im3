# ================================================================
# Makefile — v3 聊天系统
#
# 用法：
#   make           → 编译 Linux 版（在 WSL/Ubuntu 中运行）
#   make clean     → 清理
#
# Linux 依赖：nasm, gcc, make
# ================================================================

CC      = gcc
NASM    = nasm
CFLAGS  = -O2 -fno-stack-protector -no-pie -fno-pie -g
NASMFLAGS = -f elf64 -g -F dwarf

# ASM 文件列表
ASM_SRCS_SERVER  = server_main.asm buffer.asm net_utils.asm
ASM_SRCS_CLIENT  = client_main.asm net_utils.asm

# 对象文件
SERVER_OBJS = server_main.o buffer.o net_utils.o auth.o platform.o
CLIENT_OBJS = client_main.o net_utils.o platform.o

.PHONY: all clean

all: server client

# ---- 编译 ASM ----
%.o: %.asm calling.inc
	$(NASM) $(NASMFLAGS) $< -o $@

# ---- 编译 C ----
%.o: %.c platform.h
	$(CC) $(CFLAGS) -c $< -o $@

# ---- 链接 ----
server: $(SERVER_OBJS)
	$(CC) -no-pie -g -o $@ $^

client: $(CLIENT_OBJS)
	$(CC) -no-pie -g -o $@ $^

# ---- 清理 ----
clean:
	rm -f *.o server client
