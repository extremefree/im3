/* test_auth3.c */
#include <stdio.h>
#include <string.h>

/* 直接内联 auth 逻辑测试 */
extern int util_strcmp(const char *a, const char *b);
extern void util_xor_crypt(void *data, int len, const char *key, int keylen);
extern int  plat_read_file(const char *path, void *buf, int maxlen);
extern int  plat_write_file(const char *path, const void *buf, int len);

#define NAME_LEN 32
#define PASS_LEN 64
#define MAX_USERS 64
#define XOR_KEY       "ChatServerV3Key!"
#define XOR_KEY_LEN   16

struct user {
    char name[NAME_LEN];
    char pass[PASS_LEN];
};

int main() {
    /* 手动创建用户 */
    struct user users[2];
    memset(users, 0, sizeof(users));
    strcpy(users[0].name, "alice");
    strcpy(users[0].pass, "alice123");

    /* 测试 strcmp */
    printf("strcmp(alice, alice) = %d\n", util_strcmp(users[0].name, "alice"));
    printf("strcmp(alice123, alice123) = %d\n", util_strcmp(users[0].pass, "alice123"));

    /* 测试加密/解密 */
    char buf[256];
    memset(buf, 0, sizeof(buf));
    strcpy(buf, "alice:alice123\nbob:bob456\n");
    int len = (int)strlen(buf);
    printf("plaintext (%d): ", len);
    fwrite(buf, 1, len, stdout);
    printf("\n");

    util_xor_crypt(buf, len, XOR_KEY, XOR_KEY_LEN);
    printf("encrypted (%d): ", len);
    for (int i = 0; i < len; i++) printf("%02x ", (unsigned char)buf[i]);
    printf("\n");

    util_xor_crypt(buf, len, XOR_KEY, XOR_KEY_LEN);
    printf("decrypted: ");
    fwrite(buf, 1, len, stdout);
    printf("\n");

    /* 测试完整文件读写 */
    memset(buf, 0, sizeof(buf));
    strcpy(buf, "alice:alice123\nbob:bob456\n");
    len = (int)strlen(buf);
    util_xor_crypt(buf, len, XOR_KEY, XOR_KEY_LEN);
    plat_write_file("/tmp/test_users.dat", buf, len);

    char buf2[256];
    int rlen = plat_read_file("/tmp/test_users.dat", buf2, 255);
    printf("read %d bytes\n", rlen);
    util_xor_crypt(buf2, rlen, XOR_KEY, XOR_KEY_LEN);
    buf2[rlen] = 0;
    printf("content: %s", buf2);

    return 0;
}
