/*
 * client.c — v4-c 客户端（纯C，二进制帧 + ChaCha20 + X25519）
 *
 * 命令：
 *   LOGIN user:pass
 *   REGISTER user:pass
 *   mail -o <to> -m "<text>"
 *   <其他文本> → PKT_MSG
 */
#include "proto.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void x25519_base(uint8_t *out, const uint8_t *scalar);
void x25519(uint8_t *out, const uint8_t *scalar, const uint8_t *point);
void chacha20_encrypt(uint8_t *out, const uint8_t *in, int len,
                      const uint8_t *key, const uint8_t *nonce8, uint64_t ctr);

static uint8_t g_my_priv[PUBKEY_LEN];
static uint8_t g_my_pub[PUBKEY_LEN];
static uint8_t g_shared[SHARED_LEN];
static uint64_t g_tx_nonce = 0;
static int g_handshaked = 0;
static int g_sock = -1;

/* ---------------------------------------------------------------- */
static void send_frame(uint8_t type, uint8_t flags,
                        const void *payload, int plen) {
    frame_hdr_t hdr;
    hdr.type  = type;
    hdr.flags = flags;
    hdr.len   = (uint16_t)plen;
    plat_write(g_sock, &hdr, sizeof(hdr));
    if (plen > 0) plat_write(g_sock, payload, plen);
}

static void send_encrypted(uint8_t type, const void *payload, int plen) {
    if (!g_handshaked) {
        send_frame(type, 0, payload, plen);
        return;
    }
    static uint8_t enc_buf[NONCE_LEN + MAX_PAYLOAD];
    uint64_t nonce = g_tx_nonce++;
    memcpy(enc_buf, &nonce, 8);
    uint8_t nonce8[8];
    memcpy(nonce8, &nonce, 8);
    chacha20_encrypt(enc_buf + NONCE_LEN, payload, plen, g_shared, nonce8, 0);

    frame_hdr_t hdr;
    hdr.type  = type;
    hdr.flags = 0;
    hdr.len   = (uint16_t)(NONCE_LEN + plen);
    plat_write(g_sock, &hdr, sizeof(hdr));
    plat_write(g_sock, enc_buf, NONCE_LEN + plen);
}

/* ---------------------------------------------------------------- */
/* 解析 "user:pass" → "user\0pass\0"，返回长度 */
static int build_login_payload(uint8_t *dst, const char *src) {
    const char *colon = strchr(src, ':');
    if (!colon) return 0;
    int ulen = (int)(colon - src);
    int plen = (int)strlen(colon + 1);
    memcpy(dst, src, ulen);
    dst[ulen] = '\0';
    memcpy(dst + ulen + 1, colon + 1, plen);
    dst[ulen + 1 + plen] = '\0';
    return ulen + 1 + plen + 1;
}

/* 解析 mail -o <to> -m <text> */
static int parse_mail(const char *line, char *to_out, char *text_out) {
    const char *p = line;
    to_out[0] = text_out[0] = '\0';

    /* 找 -o */
    while (*p) {
        if (p[0] == '-' && p[1] == 'o' && p[2] == ' ') {
            p += 3;
            int i = 0;
            while (*p && *p != ' ' && i < 63) to_out[i++] = *p++;
            to_out[i] = '\0';
        } else if (p[0] == '-' && p[1] == 'm' && p[2] == ' ') {
            p += 3;
            if (*p == '"') p++;
            int i = 0;
            while (*p && *p != '"' && i < (MAX_PAYLOAD - 80))
                text_out[i++] = *p++;
            text_out[i] = '\0';
            break;
        } else {
            p++;
        }
    }
    return (to_out[0] && text_out[0]) ? 0 : -1;
}

/* ---------------------------------------------------------------- */
int main(int argc, char **argv) {
    if (argc < 2) {
        plat_print("Usage: client <host> [port]\n", 27);
        return 1;
    }

    if (plat_init() != 0) return 1;

    /* 生成密钥对 */
    plat_random(g_my_priv, PUBKEY_LEN);
    g_my_priv[0]  &= 0xF8;
    g_my_priv[31] &= 0x7F;
    g_my_priv[31] |= 0x40;
    x25519_base(g_my_pub, g_my_priv);

    /* 解析 host/port */
    const char *host = argv[1];
    int port = (argc >= 3) ? atoi(argv[2]) : 9000;

    g_sock = plat_socket6();
    if (g_sock < 0) return 1;

    static uint8_t addr[28];
    plat_resolve6(host, port, addr);
    if (plat_connect(g_sock, addr, 28) != 0) {
        plat_print("connect failed\n", 15);
        return 1;
    }

    plat_print("[v4c-client] connected. Sending hello...\n", 41);

    /* 发送 PKT_HELLO */
    send_frame(PKT_HELLO, 0, g_my_pub, PUBKEY_LEN);

    static uint8_t fds[PLAT_FD_SET_SIZE];
    static uint8_t line_buf[2048];
    static uint8_t payload_buf[NONCE_LEN + MAX_PAYLOAD + 64];
    static uint8_t send_buf[MAX_PAYLOAD];

    for (;;) {
        plat_fd_zero(fds);
        plat_fd_set(g_sock, fds);
        plat_client_add_stdin(fds);

        if (plat_select(1024, fds) <= 0) continue;

        /* stdin 就绪 */
        if (plat_stdin_ready(fds)) {
            int n = plat_read_stdin(line_buf, sizeof(line_buf) - 1);
            if (n <= 0) break;
            if (line_buf[n-1] == '\n') n--;
            line_buf[n] = '\0';
            if (n == 0) continue;

            char *line = (char *)line_buf;

            if (strncmp(line, "mail ", 5) == 0) {
                /* mail -o X -m Y */
                char to[64], text[MAX_PAYLOAD - 80];
                if (parse_mail(line + 5, to, text) != 0) continue;
                int tlen = (int)strlen(to);
                int msglen = (int)strlen(text);
                memcpy(send_buf, to, tlen);
                send_buf[tlen] = '\0';
                memcpy(send_buf + tlen + 1, text, msglen);
                send_encrypted(PKT_MAIL, send_buf, tlen + 1 + msglen);

            } else if (strncmp(line, "LOGIN ", 6) == 0) {
                int len = build_login_payload(send_buf, line + 6);
                if (len <= 0) continue;
                send_encrypted(PKT_LOGIN, send_buf, len);

            } else if (strncmp(line, "REGISTER ", 9) == 0) {
                int len = build_login_payload(send_buf, line + 9);
                if (len <= 0) continue;
                send_encrypted(PKT_REGISTER, send_buf, len);

            } else {
                send_encrypted(PKT_MSG, line, n);
            }
        }

        /* 服务器数据 */
        if (plat_fd_isset(g_sock, fds)) {
            frame_hdr_t hdr;
            if (plat_read(g_sock, &hdr, sizeof(hdr)) != sizeof(hdr)) break;
            uint8_t type  = hdr.type;
            uint16_t plen = hdr.len;

            if (plen > NONCE_LEN + MAX_PAYLOAD) break;

            if (plen > 0) {
                if (plat_read(g_sock, payload_buf, plen) != plen) break;
            }

            /* 解密 */
            int content_len = (int)plen;
            uint8_t *content = payload_buf;
            if (g_handshaked && plen >= NONCE_LEN) {
                uint8_t nonce8[8];
                memcpy(nonce8, payload_buf, 8);
                content_len = plen - NONCE_LEN;
                content = payload_buf + NONCE_LEN;
                chacha20_encrypt(content, content, content_len,
                                 g_shared, nonce8, 0);
            }
            content[content_len] = '\0';

            switch (type) {
            case PKT_HELLO:
                if (plen != PUBKEY_LEN) break;
                x25519(g_shared, g_my_priv, payload_buf);
                g_handshaked = 1;
                plat_print("[v4c-client] handshake OK. You can LOGIN.\n", 42);
                break;

            case PKT_ACK: {
                if (content_len < 1) break;
                if (content[0] == ACK_OK)
                    plat_print("[OK]\n", 5);
                else
                    plat_print("[FAIL]\n", 7);
                break;
            }
            case PKT_MSG:
            case PKT_MAIL:
            case PKT_ANNOUNCE:
                plat_write(1, content, content_len);
                plat_print("\n", 1);
                break;

            case PKT_PONG:
                break;
            default:
                break;
            }
        }
    }

    plat_cleanup();
    return 0;
}
