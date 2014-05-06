#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

static char *fdgets(char *line, size_t maxsize, int fd) {
    char c;
    int n = 0;
    while (n < (maxsize-1) && read(fd, &c, 1) == 1) {
        line[n++] = c;
        if (c == '\n') break;
    }
    line[n] = 0;
    return n ? line : NULL;
}

int lport_to_uid(uint16_t lport) {
    int uid;
    int fd = -1;
    char buf[2048];
    uint32_t inode;

    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "fopen: /proc/net/tcp: %s\n", strerror(errno));
        return (-1);
    }

    /* Eat the header line. */
    fdgets(buf, sizeof(buf), fd);

    while (fdgets(buf, sizeof(buf), fd)) {
        int ret;
        uint32_t portl_temp;
        uint32_t portf_temp;
        uint16_t portl;
        uint16_t portf;
        in_addr_t local;
        in_addr_t remote;

        ret = sscanf(buf,
            "%*d: %x:%x %x:%x %*x %*x:%*x %*x:%*x %*x %d %*d %u",
            &local, &portl_temp, &remote, &portf_temp, &uid, &inode);

        if (ret != 6)
            continue;

        portl = (uint16_t) portl_temp;
        portf = (uint16_t) portf_temp;

        if (portl == lport) {
            goto out_success;
        }
    }
    close(fd);
    return (-1);

out_success:
    close(fd);
    /*
    ** If the inode is zero, the socket is dead, and its owner
    ** has probably been set to root.  It would be incorrect
    ** to return a successful response here.
    */
    if (inode == 0 && uid == 0)
        return (-1);
    return (uid);
}
