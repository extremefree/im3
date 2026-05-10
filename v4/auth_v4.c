/*
 * auth_v4.c — v4 用户认证 + X25519 密钥管理
 *
 * 用户文件：im_users.dat（与 v3 格式相同，XOR 加密）
 * 密钥文件：keys/<username>.pub  (32字节原始公钥)
 *           keys/<username>.priv (32字节，XOR 加密的私钥)
 *
 * 新增接口（在 v3 auth 基础上扩展）：
 *   auth_load_pubkey(name, pub[32])     — 加载公钥
 *   auth_save_keypair(name, pub, priv)  — 保存密钥对
 */
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

extern int  util_strlen(const char *s);
extern int  util_strcmp(const char *a, const char *b);
extern int  util_strncmp(const char *a, const char *b, int n);
extern void util_xor_crypt(void *data, int len, const char *key, int keylen);
extern int  util_find_colon(const char *s, int len);

static void auth_save(void);

#define MAX_CLIENTS   32
#define MAX_USERS     64
#define NAME_LEN      32
#define PASS_LEN      64
#define RATE_LIMIT    10
#ifdef _WIN32
#define USERS_FILE    "im_users.dat"
#define KEYS_DIR      "keys"
#else
#define USERS_FILE    "/tmp/im_users.dat"
#define KEYS_DIR      "/tmp/im_keys"
#endif
#define XOR_KEY       "ChatServerV4Key!"
#define XOR_KEY_LEN   16

struct user {
    char name[NAME_LEN];
    char pass[PASS_LEN];
};

static struct user g_users[MAX_USERS];
static int         g_user_count = 0;

struct session {
    int  fd;
    int  user_idx;
    int  msg_count;
    time_t last_reset;
};

static struct session g_sessions[MAX_CLIENTS];

static struct session *find_session(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_sessions[i].fd == fd)
            return &g_sessions[i];
    return NULL;
}

static int find_user(const char *name) {
    for (int i = 0; i < g_user_count; i++)
        if (util_strcmp(g_users[i].name, name) == 0)
            return i;
    return -1;
}

/* ================================================================
 * auth_init
 * ================================================================ */
void auth_init(void) {
    char buf[8192];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_sessions[i].fd = -1;
        g_sessions[i].user_idx = -1;
    }
    plat_mkdir(KEYS_DIR);

    int len = plat_read_file(USERS_FILE, buf, (int)sizeof(buf) - 1);
    if (len <= 0) {
        strcpy(g_users[0].name, "alice");
        strcpy(g_users[0].pass, "alice123");
        strcpy(g_users[1].name, "bob");
        strcpy(g_users[1].pass, "bob456");
        g_user_count = 2;
        auth_save();
        return;
    }
    util_xor_crypt(buf, len, XOR_KEY, XOR_KEY_LEN);
    buf[len] = '\0';

    char *p = buf;
    while (*p && g_user_count < MAX_USERS) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';
        int line_len = (int)(eol ? (eol - p) : (long)strlen(p));
        if (line_len == 0) { if (eol) { p = eol + 1; continue; } break; }
        int ci = util_find_colon(p, line_len);
        if (ci > 0 && ci < NAME_LEN && (line_len - ci - 1) < PASS_LEN) {
            strncpy(g_users[g_user_count].name, p, ci);
            g_users[g_user_count].name[ci] = '\0';
            strncpy(g_users[g_user_count].pass, p + ci + 1, line_len - ci - 1);
            g_users[g_user_count].pass[line_len - ci - 1] = '\0';
            g_user_count++;
        }
        if (eol) p = eol + 1; else break;
    }
}

/* ================================================================
 * auth_save（内部）
 * ================================================================ */
static void auth_save(void) {
    char buf[8192];
    int pos = 0;
    for (int i = 0; i < g_user_count; i++) {
        int nl = (int)strlen(g_users[i].name);
        int pl = (int)strlen(g_users[i].pass);
        if (pos + nl + 1 + pl + 1 >= (int)sizeof(buf)) break;
        memcpy(buf + pos, g_users[i].name, nl); pos += nl;
        buf[pos++] = ':';
        memcpy(buf + pos, g_users[i].pass, pl); pos += pl;
        buf[pos++] = '\n';
    }
    util_xor_crypt(buf, pos, XOR_KEY, XOR_KEY_LEN);
    plat_write_file(USERS_FILE, buf, pos);
}

/* ================================================================
 * 会话管理
 * ================================================================ */
void auth_new_session(int fd) {
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

void auth_remove_session(int fd) {
    struct session *s = find_session(fd);
    if (s) { s->fd = -1; s->user_idx = -1; }
}

/* ================================================================
 * auth_login(fd, name, nlen, pass, plen) → 0=ok, -1=fail
 * ================================================================ */
int auth_login(int fd, const char *name, int nlen, const char *pass, int plen) {
    if (nlen <= 0 || nlen >= NAME_LEN) return -1;
    if (plen <= 0 || plen >= PASS_LEN) return -1;

    char nbuf[NAME_LEN], pbuf[PASS_LEN];
    strncpy(nbuf, name, nlen); nbuf[nlen] = '\0';
    strncpy(pbuf, pass, plen); pbuf[plen] = '\0';

    int idx = find_user(nbuf);
    if (idx < 0) return -1;
    if (util_strcmp(g_users[idx].pass, pbuf) != 0) return -1;

    struct session *s = find_session(fd);
    if (!s) return -1;
    s->user_idx = idx;
    return 0;
}

/* ================================================================
 * auth_register(fd, name, nlen, pass, plen) → 0=ok, -1=dup/err
 * ================================================================ */
int auth_register(int fd, const char *name, int nlen, const char *pass, int plen) {
    if (nlen <= 0 || nlen >= NAME_LEN) return -1;
    if (plen <= 0 || plen >= PASS_LEN) return -1;
    if (g_user_count >= MAX_USERS) return -1;

    char nbuf[NAME_LEN], pbuf[PASS_LEN];
    strncpy(nbuf, name, nlen); nbuf[nlen] = '\0';
    strncpy(pbuf, pass, plen); pbuf[plen] = '\0';

    if (find_user(nbuf) >= 0) return -1;  /* 用户已存在 */

    strncpy(g_users[g_user_count].name, nbuf, NAME_LEN - 1);
    strncpy(g_users[g_user_count].pass, pbuf, PASS_LEN - 1);
    g_user_count++;
    auth_save();

    /* 自动登录 */
    return auth_login(fd, name, nlen, pass, plen);
}

/* ================================================================
 * auth_logout(fd)
 * ================================================================ */
void auth_logout(int fd) {
    struct session *s = find_session(fd);
    if (s) s->user_idx = -1;
}

/* ================================================================
 * auth_get_name(fd, out_name) → 0=ok, -1=未登录
 * ================================================================ */
int auth_get_name(int fd, char *out_name) {
    struct session *s = find_session(fd);
    if (!s || s->user_idx < 0) return -1;
    strcpy(out_name, g_users[s->user_idx].name);
    return 0;
}

int auth_is_logged_in(int fd) {
    struct session *s = find_session(fd);
    return (s && s->user_idx >= 0) ? 1 : 0;
}

int auth_get_user_idx(int fd) {
    struct session *s = find_session(fd);
    return (s) ? s->user_idx : -1;
}

int auth_ratelimit(int fd) {
    struct session *s = find_session(fd);
    if (!s) return 1;
    time_t now = time(NULL);
    if (now > s->last_reset) {
        s->msg_count = 0;
        s->last_reset = now;
    }
    if (s->msg_count >= RATE_LIMIT) return 1;
    s->msg_count++;
    return 0;
}

/* ================================================================
 * 密钥文件 I/O
 * ================================================================ */

/* auth_load_pubkey(name, pub[32]) → 0=ok, -1=not found */
int auth_load_pubkey(const char *name, unsigned char *pub) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.pub", KEYS_DIR, name);
    int n = plat_read_file(path, pub, 32);
    return (n == 32) ? 0 : -1;
}

/* auth_save_keypair(name, pub[32], priv[32]) → 0=ok */
int auth_save_keypair(const char *name, const unsigned char *pub,
                      const unsigned char *priv) {
    char path[256];
    char encpriv[32];

    /* 保存公钥（明文） */
    snprintf(path, sizeof(path), "%s/%s.pub", KEYS_DIR, name);
    if (plat_write_file(path, pub, 32) != 32) return -1;

    /* 保存私钥（XOR 加密） */
    memcpy(encpriv, priv, 32);
    util_xor_crypt(encpriv, 32, XOR_KEY, XOR_KEY_LEN);
    snprintf(path, sizeof(path), "%s/%s.priv", KEYS_DIR, name);
    if (plat_write_file(path, encpriv, 32) != 32) return -1;

    return 0;
}

/* auth_load_privkey(name, priv[32]) → 0=ok */
int auth_load_privkey(const char *name, unsigned char *priv) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.priv", KEYS_DIR, name);
    int n = plat_read_file(path, priv, 32);
    if (n != 32) return -1;
    util_xor_crypt(priv, 32, XOR_KEY, XOR_KEY_LEN);
    return 0;
}
