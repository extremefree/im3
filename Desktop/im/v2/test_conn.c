#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
int main() {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    printf("socket: %d\n", fd);
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(9000);
    inet_pton(AF_INET6, "::1", &addr.sin6_addr);
    int r = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    printf("connect: %d, errno: %d\n", r, errno);
    perror("connect");
    close(fd);
    return 0;
}
