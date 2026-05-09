/* test_auth.c — 测试 auth 模块 */
#include <stdio.h>

extern void auth_init(void);
extern int auth_login(int fd, const char *name, int nlen, const char *pass, int plen);
extern const char *auth_get_name(int fd);
extern int auth_is_logged_in(int fd);

int main() {
    auth_init();

    /* 模拟 fd=5 登录 alice */
    int r = auth_login(5, "alice", 5, "alice123", 8);
    printf("auth_login(5, \"alice\", 5, \"alice123\", 8) = %d (expect 0)\n", r);

    if (r == 0) {
        printf("logged in: %d\n", auth_is_logged_in(5));
        printf("name: %s\n", auth_get_name(5));
    }

    return 0;
}
