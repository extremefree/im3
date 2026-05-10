/*
 * utils.c — v4-c 工具函数（对应 v4/net_utils.asm 的 C 实现）
 */
#include <string.h>

int util_strlen(const char *s) {
    return (int)strlen(s);
}

int util_strcmp(const char *a, const char *b) {
    return strcmp(a, b);
}

int util_strncmp(const char *a, const char *b, int n) {
    return strncmp(a, b, (size_t)n);
}

void util_xor_crypt(void *data, int len, const char *key, int keylen) {
    unsigned char *d = (unsigned char *)data;
    for (int i = 0; i < len; i++)
        d[i] ^= (unsigned char)key[i % keylen];
}

/* 找第一个 ':' 的位置，找不到返回 -1 */
int util_find_colon(const char *s, int len) {
    for (int i = 0; i < len; i++)
        if (s[i] == ':') return i;
    return -1;
}
