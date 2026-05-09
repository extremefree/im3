/* test_auth2.c */
#include <stdio.h>
#include <string.h>

extern void auth_init(void);
extern void auth_save(void);
extern int auth_login(int fd, const char *name, int nlen, const char *pass, int plen);

/* 检查内部状态 - 直接读 user 结构 */
extern char *g_users;  /* hack */

int main() {
    auth_init();

    /* 直接测试：把 name 和 pass 打印出来看 */
    char name[32] = {0};
    char pass[64] = {0};
    memcpy(name, "alice", 5);
    memcpy(pass, "alice123", 8);

    printf("name='%s' pass='%s'\n", name, pass);

    int r = auth_login(5, name, 5, pass, 8);
    printf("auth_login = %d\n", r);

    /* 测试：用不同方式 */
    r = auth_login(6, "alice", 5, "alice123", 8);
    printf("auth_login (string literal) = %d\n", r);

    return 0;
}
