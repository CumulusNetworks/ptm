/* Copyright 2013 Cumulus Networks, Inc.  All rights reserved. */

#ifndef _PTM_QUAGGA_IF_H_
#define _PTM_QUAGGA_IF_H_

#include <sys/un.h>

struct ptm_quagga_msg {
    struct sockaddr_in lin;
    char lport[IF_NAMESIZE];
};

typedef enum {
    DIR_SERVER,
    DIR_CLIENT,
    DIR_UNKNOWN,
} ptm_quagga_dir;

#define CHECK_ERROR(a, b) {                                \
        if (a < 0) {                                       \
            perror(b);                                     \
            goto error_out;                                \
        }                                                  \
    }

const char PTMD_QUAGGA_SOCKET[] = "\0/var/run/ptmd-quagga.socket";

/* Function takes and FD and a direction [client/server]
 * which returns the accepted socket for the SERVER direction
 */

static inline
int ptm_quagga_connect(int *in_fd, ptm_quagga_dir dir)
{
    struct sockaddr_un addr;
    int flags;
    int rc;

    flags = SOCK_STREAM | SOCK_CLOEXEC;
    *in_fd = socket(AF_UNIX, flags, 0);
    CHECK_ERROR(*in_fd,"socket() failed");

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, PTMD_QUAGGA_SOCKET, sizeof(PTMD_QUAGGA_SOCKET));

    if (dir == DIR_SERVER) {

        unlink(addr.sun_path);
        rc = bind(*in_fd, (struct sockaddr*)&addr,
                  sizeof(addr.sun_family) + sizeof(PTMD_QUAGGA_SOCKET) -1);
        CHECK_ERROR(rc, "bind() failed");

        rc = listen(*in_fd, 1);
        CHECK_ERROR(rc, "listen() failed");

        fprintf(stderr, "socket ready\n");

    } else if (dir == DIR_CLIENT) {

        rc = connect(*in_fd, (struct sockaddr *)&addr, SUN_LEN(&addr));
        CHECK_ERROR(rc, "connect() failed");
    }

    return 0;

error_out:
    close (*in_fd);
    return errno;
}

#endif // _PTM_QUAGGA_IF_H_
