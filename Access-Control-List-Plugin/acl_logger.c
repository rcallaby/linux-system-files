#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <sys/socket.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

int main() {
    struct sockaddr_nl src_addr;
    struct nlmsghdr *nlh = NULL;
    int sock_fd;

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) return -1;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_groups = 1;  // subscribe to group 1

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    while (1) {
        recv(sock_fd, nlh, NLMSG_SPACE(MAX_PAYLOAD), 0);
        printf("Kernel: %s\n", (char *)NLMSG_DATA(nlh));
    }

    close(sock_fd);
    free(nlh);
    return 0;
}
