/* test_strcmp.c */
#include <stdio.h>

extern int util_strcmp(const char *a, const char *b);

int main() {
    int r1 = util_strcmp("alice123", "alice123");
    int r2 = util_strcmp("alice123", "bob456");
    int r3 = util_strcmp("alice", "alice");
    printf("strcmp(\"alice123\", \"alice123\") = %d (expect 0)\n", r1);
    printf("strcmp(\"alice123\", \"bob456\") = %d (expect 1)\n", r2);
    printf("strcmp(\"alice\", \"alice\") = %d (expect 0)\n", r3);
    return 0;
}
