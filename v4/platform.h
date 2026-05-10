#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>
#include <stddef.h>

/* ---- Init / Cleanup ---- */
int  plat_init(void);
void plat_cleanup(void);

/* ---- Socket ---- */
int  plat_socket6(void);
int  plat_set_reuse(int fd);
int  plat_bind(int fd, const void *addr, int len);
int  plat_listen(int fd, int backlog);
int  plat_accept(int fd, void *addr, void *addrlen);
int  plat_connect(int fd, const void *addr, int len);
void plat_close(int fd);

/* ---- I/O ---- */
int  plat_read(int fd, void *buf, int len);
int  plat_write(int fd, const void *buf, int len);
void plat_print(const char *msg, int len);

/* ---- Select / fd_set ---- */
#define PLAT_FD_SET_SIZE  520   /* enough for both Linux (128) and Win (516) */
int  plat_select(int maxfd, void *readfds);
void plat_fd_zero(void *fds);
void plat_fd_set(int fd, void *fds);
void plat_fd_clr(int fd, void *fds);
int  plat_fd_isset(int fd, void *fds);
void plat_fd_copy(void *dst, const void *src);  /* memcpy fd_set */

/* ---- Address ---- */
int  plat_resolve6(const char *addrstr, uint16_t port, void *out);

/* ---- Client helpers ---- */
void plat_client_add_stdin(void *fds);   /* no-op on Windows */
int  plat_stdin_ready(void *fds);        /* check stdin, using fds on Linux */
int  plat_read_stdin(void *buf, int len);

/* ---- File I/O ---- */
int  plat_read_file(const char *path, void *buf, int maxlen);
int  plat_write_file(const char *path, const void *buf, int len);

/* ---- Crypto helpers ---- */
int  plat_random(void *buf, int len);   /* CSPRNG: getrandom/BCryptGenRandom */
int  plat_mkdir(const char *path);      /* 创建目录（已存在则忽略错误）*/

#endif
