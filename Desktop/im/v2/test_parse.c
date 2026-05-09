/* test_parse.c — 测试 util_strncmp 和行解析 */
#include <stdio.h>
#include <string.h>

extern int util_strncmp(const char *a, const char *b, int n);
extern int util_find_colon(const char *s, int len);

int main() {
    const char *line = "LOGIN alice:alice123";
    const char *prefix_reg = "/REGISTER ";
    const char *prefix_login = "LOGIN ";

    int r1 = util_strncmp(line, prefix_reg, 10);
    printf("strncmp(\"%s\", \"%s\", 10) = %d (expect 1)\n", line, prefix_reg, r1);

    int r2 = util_strncmp(line, prefix_login, 6);
    printf("strncmp(\"%s\", \"%s\", 6) = %d (expect 0)\n", line, prefix_login, r2);

    int ci = util_find_colon(line + 6, 15);
    printf("find_colon(\"%s\", 15) = %d (expect 5)\n", line + 6, ci);

    return 0;
}
