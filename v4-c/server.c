/*
 * server.c — v4-c 服务器（纯C，二进制帧 + ChaCha20 + X25519）
 */
#include "proto.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* 密码库 */
void x25519_base(uint8_t *out, const uint8_t *scalar);
void x25519(uint8_t *out, const uint8_t *scalar, const uint8_t *point);
void chacha20_encrypt(uint8_t *out, const uint8_t *in, int len,
                      const uint8_t *key, const uint8_t *nonce8, uint64_t ctr);

/* 认证 */
void auth_init(void);
void auth_new_session(int fd);
void auth_remove_session(int fd);
int  auth_login(int fd, const char *name, int nlen, const char *pass, int plen);
int  auth_register(int fd, const char *name, int nlen, const char *pass, int plen);
void auth_logout(int fd);
int  auth_get_name(int fd, char *out);
int  auth_is_logged_in(int fd);

/* 工具 */
extern void util_xor_crypt(void *data, int len, const char *key, int keylen);

#define MAX_CLIENTS 32

static client_state_t g_clients[MAX_CLIENTS];
static int g_listen_fd = -1;
static uint8_t g_server_priv[PUBKEY_LEN];
static uint8_t g_server_pub[PUBKEY_LEN];

/* ---------------------------------------------------------------- */
static client_state_t *find_client(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_clients[i].fd == fd)
            return &g_clients[i];
    return NULL;
}

static void send_frame(int fd, uint8_t type, uint8_t flags,
                       const void *payload, int plen) {
    frame_hdr_t hdr;
    hdr.type  = type;
    hdr.flags = flags;
    hdr.len   = (uint16_t)plen;
    plat_write(fd, &hdr, sizeof(hdr));
    if (plen > 0) plat_write(fd, payload, plen);
}

static void send_encrypted(client_state_t *cs, uint8_t type,
                            const void *payload, int plen) {
    if (!(cs->flags & CSF_HANDSHAKED)) {
        send_frame(cs->fd, type, 0, payload, plen);
        return;
    }
    /* 构造 [nonce:8][encrypted_payload] */
    static uint8_t enc_buf[NONCE_LEN + MAX_PAYLOAD];
    uint64_t nonce = cs->tx_nonce++;
    memcpy(enc_buf, &nonce, 8);
    uint8_t nonce8[8];
    memcpy(nonce8, &nonce, 8);
    chacha20_encrypt(enc_buf + NONCE_LEN, payload, plen, cs->shared, nonce8, 0);

    frame_hdr_t hdr;
    hdr.type  = type;
    hdr.flags = 0;
    hdr.len   = (uint16_t)(NONCE_LEN + plen);
    plat_write(cs->fd, &hdr, sizeof(hdr));
    plat_write(cs->fd, enc_buf, NONCE_LEN + plen);
}

static int recv_decrypt(client_state_t *cs, uint8_t *payload, int plen) {
    if (!(cs->flags & CSF_HANDSHAKED)) return plen;
    if (plen < NONCE_LEN) return -1;
    uint8_t nonce8[8];
    memcpy(nonce8, payload, NONCE_LEN);
    cs->rx_nonce++;
    chacha20_encrypt(payload + NONCE_LEN, payload + NONCE_LEN,
                     plen - NONCE_LEN, cs->shared, nonce8, 0);
    return plen - NONCE_LEN;
}

static void disconnect(client_state_t *cs, void *fds) {
    plat_fd_clr(cs->fd, fds);
    auth_remove_session(cs->fd);
    plat_close(cs->fd);
    cs->fd = -1;
    plat_print("[v4c-server] client disconnected\n", 34);
}

static void broadcast(int from_fd, uint8_t type,
                      const void *payload, int plen) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].fd == -1) continue;
        if (g_clients[i].fd == from_fd) continue;
        if (!(g_clients[i].flags & CSF_LOGGED_IN)) continue;
        send_encrypted(&g_clients[i], type, payload, plen);
    }
}

/* ---------------------------------------------------------------- */
int main(int argc, char **argv) {
    (void)argc; (void)argv;

    if (plat_init() != 0) return 1;
    auth_init();

    /* 生成服务器密钥对 */
    plat_random(g_server_priv, PUBKEY_LEN);
    g_server_priv[0]  &= 0xF8;
    g_server_priv[31] &= 0x7F;
    g_server_priv[31] |= 0x40;
    x25519_base(g_server_pub, g_server_priv);

    /* 初始化客户端表 */
    for (int i = 0; i < MAX_CLIENTS; i++) g_clients[i].fd = -1;

    /* 创建监听 socket */
    g_listen_fd = plat_socket6();
    if (g_listen_fd < 0) return 1;
    plat_set_reuse(g_listen_fd);

    static uint8_t addr[28];
    plat_resolve6(NULL, 9000, addr);
    plat_bind(g_listen_fd, addr, 28);
    plat_listen(g_listen_fd, MAX_CLIENTS);
    plat_print("[v4c-server] listening on [::]:9000\n", 37);

    static uint8_t fds[PLAT_FD_SET_SIZE];
    static uint8_t payload_buf[NONCE_LEN + MAX_PAYLOAD + 64];

    for (;;) {
        plat_fd_zero(fds);
        plat_fd_set(g_listen_fd, fds);
        for (int i = 0; i < MAX_CLIENTS; i++)
            if (g_clients[i].fd != -1)
                plat_fd_set(g_clients[i].fd, fds);

        if (plat_select(1024, fds) <= 0) continue;

        /* 新连接 */
        if (plat_fd_isset(g_listen_fd, fds)) {
            int fd = plat_accept(g_listen_fd, NULL, NULL);
            if (fd >= 0) {
                client_state_t *cs = NULL;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (g_clients[i].fd == -1) { cs = &g_clients[i]; break; }
                }
                if (!cs) {
                    plat_close(fd);
                } else {
                    cs->fd = fd;
                    cs->flags = 0;
                    cs->user_idx = -1;
                    cs->tx_nonce = 0;
                    cs->rx_nonce = 0;
                    cs->buf_len  = 0;
                    auth_new_session(fd);
                    /* 发送 PKT_HELLO */
                    send_frame(fd, PKT_HELLO, 0, g_server_pub, PUBKEY_LEN);
                    plat_print("[v4c-server] new connection\n", 28);
                }
            }
        }

        /* 处理客户端 */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            client_state_t *cs = &g_clients[i];
            if (cs->fd == -1) continue;
            if (!plat_fd_isset(cs->fd, fds)) continue;

            /* 读帧头 */
            frame_hdr_t hdr;
            if (plat_read(cs->fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
                disconnect(cs, fds); continue;
            }
            uint8_t type  = hdr.type;
            uint16_t plen = hdr.len;


            if (plen > NONCE_LEN + MAX_PAYLOAD) {
                disconnect(cs, fds); continue;
            }

            /* 读 payload */
            if (plen > 0) {
                if (plat_read(cs->fd, payload_buf, plen) != plen) {
                    disconnect(cs, fds); continue;
                }
            }

            /* 解密（若已握手）*/
            int content_len = (int)plen;
            uint8_t *content = payload_buf;
            if (cs->flags & CSF_HANDSHAKED) {
                content_len = recv_decrypt(cs, payload_buf, plen);
                if (content_len < 0) { disconnect(cs, fds); continue; }
                content = payload_buf + NONCE_LEN;
            }
            /* 确保 content 以 \0 结尾（便于字符串操作）*/
            content[content_len] = '\0';
            switch (type) {
            case PKT_HELLO: {
                if (plen != PUBKEY_LEN) break;
                x25519(cs->shared, g_server_priv, payload_buf);
                cs->flags |= CSF_HANDSHAKED;
                break;
            }
            case PKT_LOGIN: {
                /* payload = "user\0pass\0" */
                const char *user = (char *)content;
                int ulen = (int)strlen(user);
                const char *pass = user + ulen + 1;
                int ppass = content_len - ulen - 2;
                if (ppass < 0) {
                    uint8_t code = ACK_ERR_CRED;
                    send_encrypted(cs, PKT_ACK, &code, 1);
                    break;
                }
                if (auth_login(cs->fd, user, ulen, pass, ppass) == 0) {
                    cs->flags |= CSF_LOGGED_IN;
                    uint8_t code = ACK_OK;
                    send_encrypted(cs, PKT_ACK, &code, 1);
                } else {
                    uint8_t code = ACK_ERR_CRED;
                    send_encrypted(cs, PKT_ACK, &code, 1);
                }
                break;
            }
            case PKT_REGISTER: {
                const char *user = (char *)content;
                int ulen = (int)strlen(user);
                const char *pass = user + ulen + 1;
                int ppass = content_len - ulen - 2;
                if (ppass < 0) {
                    uint8_t code = ACK_ERR_CRED;
                    send_encrypted(cs, PKT_ACK, &code, 1);
                    break;
                }
                if (auth_register(cs->fd, user, ulen, pass, ppass) == 0) {
                    cs->flags |= CSF_LOGGED_IN;
                    uint8_t code = ACK_OK;
                    send_encrypted(cs, PKT_ACK, &code, 1);
                } else {
                    uint8_t code = ACK_ERR_EXIST;
                    send_encrypted(cs, PKT_ACK, &code, 1);
                }
                break;
            }
            case PKT_LOGOUT: {
                auth_logout(cs->fd);
                cs->flags &= ~CSF_LOGGED_IN;
                uint8_t code = ACK_OK;
                send_encrypted(cs, PKT_ACK, &code, 1);
                break;
            }
            case PKT_MSG: {
                if (!(cs->flags & CSF_LOGGED_IN)) break;
                /* 获取发送者用户名并构造消息 */
                char name[32];
                auth_get_name(cs->fd, name);
                static uint8_t msg_buf[MAX_PAYLOAD];
                int nlen = (int)strlen(name);
                int total = nlen + 2 + content_len;
                if (total < (int)sizeof(msg_buf)) {
                    memcpy(msg_buf, name, nlen);
                    msg_buf[nlen] = ':';
                    msg_buf[nlen+1] = ' ';
                    memcpy(msg_buf + nlen + 2, content, content_len);
                    broadcast(cs->fd, PKT_ANNOUNCE, msg_buf, total);
                }
                break;
            }
            case PKT_MAIL: {
                if (!(cs->flags & CSF_LOGGED_IN)) break;
                /* payload = "to\0text" */
                const char *to   = (char *)content;
                int tolen = (int)strlen(to);
                const char *text = to + tolen + 1;
                int textlen = content_len - tolen - 1;
                if (textlen < 0) break;

                /* 找目标 fd */
                for (int j = 0; j < MAX_CLIENTS; j++) {
                    if (g_clients[j].fd == -1) continue;
                    char jname[32];
                    if (auth_get_name(g_clients[j].fd, jname) != 0) continue;
                    if (strcmp(jname, to) != 0) continue;
                    /* 构造私信消息 */
                    char name[32];
                    auth_get_name(cs->fd, name);
                    static uint8_t mail_buf[MAX_PAYLOAD];
                    int nl = (int)strlen(name);
                    int total = nl + 9 + textlen;
                    if (total < (int)sizeof(mail_buf)) {
                        memcpy(mail_buf, "[mail from ", 11);
                        memcpy(mail_buf + 11, name, nl);
                        mail_buf[11 + nl] = ']';
                        mail_buf[12 + nl] = ' ';
                        memcpy(mail_buf + 13 + nl, text, textlen);
                        send_encrypted(&g_clients[j], PKT_MAIL,
                                       mail_buf, 13 + nl + textlen);
                    }
                    break;
                }
                break;
            }
            case PKT_PING: {
                uint8_t dummy = 0;
                send_encrypted(cs, PKT_PONG, &dummy, 0);
                break;
            }
            default:
                break;
            }
        }
    }
}
