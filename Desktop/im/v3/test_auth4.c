/* test_auth4.c — 完整 auth 测试 */
#include <stdio.h>
#include <string.h>

extern void auth_init(void);
extern void auth_add_session(int fd);
extern int auth_login(int fd, const char *name, int nlen, const char *pass, int plen);
extern const char *auth_get_name(int fd);
extern int auth_is_logged_in(int fd);

int main() {
    /* 清除旧文件 */
    remove("users.dat");

    auth_init();
    auth_add_session(5);

    printf("is_logged_in(5) = %d\n", auth_is_logged_in(5));

    int r = auth_login(5, "alice", 5, "alice123", 8);
    printf("auth_login(5, \"alice\", 5, \"alice123\", 8) = %d\n", r);

    if (r == 0) {
        printf("logged in: %d\n", auth_is_logged_in(5));
        printf("name: %s\n", auth_get_name(5));
    } else {
        printf("FAILED\n");
    }

    return 0;
}
