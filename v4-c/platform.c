/*
 * platform.c — 跨平台抽象层
 *
 * Linux:  POSIX syscalls
 * Windows: Winsock2 + Win32 API
 */
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <io.h>
  #include <conio.h>
  #include <bcrypt.h>
  #include <direct.h>
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <sys/random.h>
  #include <errno.h>
#endif

/* ================================================================
 * Init / Cleanup
 * ================================================================ */
int plat_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
#endif
    return 0;
}

void plat_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* ================================================================
 * Socket
 * ================================================================ */
int plat_socket6(void) {
    return (int)socket(AF_INET6, SOCK_STREAM, 0);
}

int plat_set_reuse(int fd) {
    int on = 1;
#ifdef _WIN32
    setsockopt((SOCKET)fd, SOL_SOCKET, SO_REUSEADDR,
               (const char*)&on, sizeof(on));
#else
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#endif
    /* also set IPV6_V6ONLY = 0 so we can accept IPv4-mapped connections */
    int only = 0;
#ifdef _WIN32
    setsockopt((SOCKET)fd, IPPROTO_IPV6, IPV6_V6ONLY,
               (const char*)&only, sizeof(only));
#else
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only));
#endif
    return 0;
}

int plat_bind(int fd, const void *addr, int len) {
#ifdef _WIN32
    return bind((SOCKET)fd, (const struct sockaddr*)addr, len);
#else
    return bind(fd, (const struct sockaddr*)addr, (socklen_t)len);
#endif
}

int plat_listen(int fd, int backlog) {
#ifdef _WIN32
    return listen((SOCKET)fd, backlog);
#else
    return listen(fd, backlog);
#endif
}

int plat_accept(int fd, void *addr, void *addrlen) {
#ifdef _WIN32
    int al = *(int*)addrlen;
    int r = (int)accept((SOCKET)fd, (struct sockaddr*)addr, &al);
    *(int*)addrlen = al;
    return r;
#else
    return (int)accept(fd, (struct sockaddr*)addr, (socklen_t*)addrlen);
#endif
}

int plat_connect(int fd, const void *addr, int len) {
#ifdef _WIN32
    return connect((SOCKET)fd, (const struct sockaddr*)addr, len);
#else
    return connect(fd, (const struct sockaddr*)addr, (socklen_t)len);
#endif
}

void plat_close(int fd) {
#ifdef _WIN32
    closesocket((SOCKET)fd);
#else
    close(fd);
#endif
}

/* ================================================================
 * I/O
 * ================================================================ */
int plat_read(int fd, void *buf, int len) {
#ifdef _WIN32
    return (int)recv((SOCKET)fd, (char*)buf, len, 0);
#else
    return (int)read(fd, buf, (size_t)len);
#endif
}

int plat_write(int fd, const void *buf, int len) {
#ifdef _WIN32
    return (int)send((SOCKET)fd, (const char*)buf, len, 0);
#else
    return (int)write(fd, buf, (size_t)len);
#endif
}

void plat_print(const char *msg, int len) {
#ifdef _WIN32
    fwrite(msg, 1, (size_t)len, stdout);
    fflush(stdout);
#else
    ssize_t _r __attribute__((unused)) = write(1, msg, (size_t)len);
    (void)_r;
#endif
}

/* ================================================================
 * Select / fd_set
 * ================================================================ */
void plat_fd_zero(void *fds) {
    memset(fds, 0, PLAT_FD_SET_SIZE);
}

int plat_select(int maxfd, void *readfds) {
#ifdef _WIN32
    struct timeval tv = {0, 100000}; /* 100ms timeout on Windows */
    return (int)select(maxfd, (fd_set*)readfds, NULL, NULL, &tv);
#else
    return (int)select(maxfd, (fd_set*)readfds, NULL, NULL, NULL);
#endif
}

void plat_fd_set(int fd, void *fds) {
#ifdef _WIN32
    {
        fd_set *s = (fd_set*)fds;
        if (s->fd_count < FD_SETSIZE)
            s->fd_array[s->fd_count++] = (SOCKET)fd;
    }
#else
    FD_SET(fd, (fd_set*)fds);
#endif
}

void plat_fd_clr(int fd, void *fds) {
#ifdef _WIN32
    {
        fd_set *s = (fd_set*)fds;
        for (u_int i = 0; i < s->fd_count; i++) {
            if (s->fd_array[i] == (SOCKET)fd) {
                while (i < s->fd_count - 1) {
                    s->fd_array[i] = s->fd_array[i+1];
                    i++;
                }
                s->fd_count--;
                break;
            }
        }
    }
#else
    FD_CLR(fd, (fd_set*)fds);
#endif
}

int plat_fd_isset(int fd, void *fds) {
#ifdef _WIN32
    {
        fd_set *s = (fd_set*)fds;
        for (u_int i = 0; i < s->fd_count; i++) {
            if (s->fd_array[i] == (SOCKET)fd) return 1;
        }
        return 0;
    }
#else
    return FD_ISSET(fd, (fd_set*)fds);
#endif
}

void plat_fd_copy(void *dst, const void *src) {
    memcpy(dst, src, PLAT_FD_SET_SIZE);
}

/* ================================================================
 * Address resolution
 * ================================================================ */
int plat_resolve6(const char *addrstr, uint16_t port, void *out) {
    struct sockaddr_in6 *a = (struct sockaddr_in6*)out;
    memset(a, 0, sizeof(*a));
    a->sin6_family = AF_INET6;
    a->sin6_port   = htons(port);
    if (inet_pton(AF_INET6, addrstr, &a->sin6_addr) != 1)
        return -1;
    return 0;
}

/* ================================================================
 * Client helpers — stdin handling
 * ================================================================ */
void plat_client_add_stdin(void *fds) {
#ifndef _WIN32
    FD_SET(0, (fd_set*)fds);
#endif
}

int plat_stdin_ready(void *fds) {
#ifdef _WIN32
    (void)fds;
    /* For pipe/console: PeekNamedPipe; fallback _kbhit */
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD avail = 0;
    if (PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL))
        return avail > 0 ? 1 : 0;
    /* Console: use _kbhit */
    return _kbhit() ? 1 : 0;
#else
    return FD_ISSET(0, (fd_set*)fds);
#endif
}

int plat_read_stdin(void *buf, int len) {
#ifdef _WIN32
    if (fgets((char*)buf, len, stdin))
        return (int)strlen((const char*)buf);
    return 0;
#else
    return (int)read(0, buf, (size_t)len);
#endif
}

/* ================================================================
 * File I/O
 * ================================================================ */
int plat_read_file(const char *path, void *buf, int maxlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    int n = (int)fread(buf, 1, (size_t)maxlen, f);
    fclose(f);
    return n;
}

int plat_write_file(const char *path, const void *buf, int len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int n = (int)fwrite(buf, 1, (size_t)len, f);
    fclose(f);
    return n;
}

/* ----------------------------------------------------------------
 * plat_random — 密码学安全随机数
 * ---------------------------------------------------------------- */
int plat_random(void *buf, int len) {
#ifdef _WIN32
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 0 : -1;
#else
    ssize_t n = getrandom(buf, (size_t)len, 0);
    return (n == len) ? 0 : -1;
#endif
}

/* ----------------------------------------------------------------
 * plat_mkdir — 创建目录（已存在不报错）
 * ---------------------------------------------------------------- */
int plat_mkdir(const char *path) {
#ifdef _WIN32
    if (CreateDirectoryA(path, NULL)) return 0;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    return -1;
#else
    if (mkdir(path, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
#endif
}

