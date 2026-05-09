/*
 * auth.c — 用户认证、会话管理、加密文件读写
 *
 * 用户文件 users.dat 格式（XOR 加密后存储）：
 *   username:password\n  （明文密码，靠文件加密保护）
 *   每行一个用户
 *
 * 提供：
 *   auth_init()       — 从文件加载用户
 *   auth_save()       — 保存用户到文件
 *   auth_login()      — 登录验证
 *   auth_register()   — 注册新用户
 *   auth_logout()     — 注销
 *   auth_get_name()   — 获取用户名
 *   auth_is_logged_in()— 是否已登录
 *   auth_ratelimit()  — 限速
 */
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ASM 工具函数 */
extern int  util_strlen(const char *s);
extern int  util_strcmp(const char *a, const char *b);
extern int  util_strncmp(const char *a, const char *b, int n);
extern void util_xor_crypt(void *data, int len, const char *key, int keylen);
extern int  util_find_colon(const char *s, int len);

/* 前向声明 */
static void auth_save(void);

#define MAX_CLIENTS   32
#define MAX_USERS     64
#define NAME_LEN      32
#define PASS_LEN      64
#define RATE_LIMIT    10      /* msgs/sec */
#ifdef _WIN32
#define USERS_FILE    "im_users.dat"
#else
#define USERS_FILE    "/tmp/im_users.dat"
#endif
#define XOR_KEY       "ChatServerV3Key!"
#define XOR_KEY_LEN   16

/* ---- 用户表 ---- */
struct user {
    char name[NAME_LEN];
    char pass[PASS_LEN];
};

static struct user g_users[MAX_USERS];
static int         g_user_count = 0;

/* ---- 会话表 ---- */
struct session {
    int  fd;
    int  user_idx;       /* -1 = 未登录 */
    int  msg_count;
    time_t last_reset;
};

static struct session g_sessions[MAX_CLIENTS];

/* ---- 内部：查找会话 ---- */
static struct session *find_session(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_sessions[i].fd == fd)
            return &g_sessions[i];
    return NULL;
}

/* ---- 内部：查找用户（按名） ---- */
static int find_user(const char *name) {
    for (int i = 0; i < g_user_count; i++)
        if (util_strcmp(g_users[i].name, name) == 0)
            return i;
    return -1;
}

/* ================================================================
 * auth_init() — 加载用户文件，初始化会话表
 * ================================================================ */
void auth_init(void) {
    char buf[8192];

    /* 初始化会话表 */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_sessions[i].fd = -1;
        g_sessions[i].user_idx = -1;
    }

    /* 读取加密文件 */
    int len = plat_read_file(USERS_FILE, buf, (int)sizeof(buf) - 1);
    if (len <= 0) {
        /* 文件不存在，创建默认用户 */
        strcpy(g_users[0].name, "alice");
        strcpy(g_users[0].pass, "alice123");
        strcpy(g_users[1].name, "bob");
        strcpy(g_users[1].pass, "bob456");
        g_user_count = 2;
        auth_save();
        return;
    }

    /* 解密 */
    util_xor_crypt(buf, len, XOR_KEY, XOR_KEY_LEN);
    buf[len] = '\0';

    /* 逐行解析 name:pass */
    char *p = buf;
    while (*p && g_user_count < MAX_USERS) {
        /* 找行尾 */
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';
        int line_len = (int)(eol ? (eol - p) : (long)strlen(p));
        if (line_len == 0) { if (eol) { p = eol+1; continue; } break; }

        int ci = util_find_colon(p, line_len);
        if (ci > 0 && ci < NAME_LEN && (line_len - ci - 1) < PASS_LEN) {
            memcpy(g_users[g_user_count].name, p, (size_t)ci);
            g_users[g_user_count].name[ci] = '\0';
            int plen = line_len - ci - 1;
            memcpy(g_users[g_user_count].pass, p + ci + 1, (size_t)plen);
            g_users[g_user_count].pass[plen] = '\0';
            g_user_count++;
        }
        if (eol) p = eol + 1; else break;
    }
}

/* ================================================================
 * auth_save() — 保存用户到加密文件
 * ================================================================ */
static void auth_save(void) {
    char buf[8192];
    int pos = 0;
    for (int i = 0; i < g_user_count; i++) {
        int nlen = (int)strlen(g_users[i].name);
        int plen = (int)strlen(g_users[i].pass);
        memcpy(buf + pos, g_users[i].name, (size_t)nlen);
        pos += nlen;
        buf[pos++] = ':';
        memcpy(buf + pos, g_users[i].pass, (size_t)plen);
        pos += plen;
        buf[pos++] = '\n';
    }
    /* 加密 */
    util_xor_crypt(buf, pos, XOR_KEY, XOR_KEY_LEN);
    plat_write_file(USERS_FILE, buf, pos);
}

/* ================================================================
 * auth_add_session(fd) — 新连接时调用，注册 fd 到会话表
 * ================================================================ */
void auth_add_session(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_sessions[i].fd == -1) {
            g_sessions[i].fd = fd;
            g_sessions[i].user_idx = -1;
            g_sessions[i].msg_count = 0;
            g_sessions[i].last_reset = time(NULL);
            return;
        }
    }
}

/* ================================================================
 * auth_remove_session(fd) — 断开时调用
 * ================================================================ */
void auth_remove_session(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_sessions[i].fd == fd) {
            g_sessions[i].fd = -1;
            g_sessions[i].user_idx = -1;
            return;
        }
    }
}

/* ================================================================
 * auth_login(fd, name, name_len, pass, pass_len) -> int
 *   0 = 成功, -1 = 凭证错误, -2 = 已登录
 * ================================================================ */
int auth_login(int fd, const char *name, int nlen, const char *pass, int plen) {
    struct session *s = find_session(fd);
    if (!s) return -1;
    if (s->user_idx >= 0) return -2;

    char nbuf[NAME_LEN], pbuf[PASS_LEN];
    if (nlen >= NAME_LEN || plen >= PASS_LEN) return -1;
    memcpy(nbuf, name, (size_t)nlen); nbuf[nlen] = '\0';
    memcpy(pbuf, pass, (size_t)plen); pbuf[plen] = '\0';

    int idx = find_user(nbuf);
    if (idx < 0 || util_strcmp(g_users[idx].pass, pbuf) != 0)
        return -1;

    s->user_idx = idx;
    return 0;
}

/* ================================================================
 * auth_register(name, name_len, pass, pass_len) -> int
 *   0 = 成功, -1 = 用户已存在, -2 = 满了
 * ================================================================ */
int auth_register(const char *name, int nlen, const char *pass, int plen) {
    if (g_user_count >= MAX_USERS) return -2;

    char nbuf[NAME_LEN];
    if (nlen >= NAME_LEN || plen >= PASS_LEN) return -1;
    memcpy(nbuf, name, (size_t)nlen); nbuf[nlen] = '\0';

    if (find_user(nbuf) >= 0) return -1;

    memcpy(g_users[g_user_count].name, nbuf, (size_t)nlen + 1);
    memcpy(g_users[g_user_count].pass, pass, (size_t)plen);
    g_users[g_user_count].pass[plen] = '\0';
    g_user_count++;
    auth_save();
    return 0;
}

/* ================================================================
 * auth_logout(fd)
 * ================================================================ */
void auth_logout(int fd) {
    struct session *s = find_session(fd);
    if (s) s->user_idx = -1;
}

/* ================================================================
 * auth_get_name(fd) -> const char*  (NULL = 未登录)
 * ================================================================ */
const char *auth_get_name(int fd) {
    struct session *s = find_session(fd);
    if (!s || s->user_idx < 0) return NULL;
    return g_users[s->user_idx].name;
}

/* ================================================================
 * auth_is_logged_in(fd) -> int (1=yes, 0=no)
 * ================================================================ */
int auth_is_logged_in(int fd) {
    struct session *s = find_session(fd);
    return (s && s->user_idx >= 0) ? 1 : 0;
}

/* ================================================================
 * auth_ratelimit(fd) -> int (0=ok, 1=超限)
 * ================================================================ */
int auth_ratelimit(int fd) {
    struct session *s = find_session(fd);
    if (!s) return 1;
    time_t now = time(NULL);
    if (now != s->last_reset) {
        s->msg_count = 0;
        s->last_reset = now;
    }
    s->msg_count++;
    return (s->msg_count > RATE_LIMIT) ? 1 : 0;
}
