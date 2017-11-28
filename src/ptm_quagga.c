/* Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "ptm_event.h"
#include "ptm_quagga_if.h"
#include "ptm_bfd.h"
#include "log.h"

#define REPLY_BUFFER 8192

/**
 * Global structure (private to this file) for bookkeeping - init params,
 * input params, statistics, and such.
 */
typedef struct {
    pid_t          pid;
    ptm_globals_t  *gbl;
    ptm_event_t    event;
    uint64_t       num_notifs;
    int            fd, fd_server;
} ptm_quagga_globals_t;

ptm_quagga_globals_t ptm_quagga;


static int
_extract_event (void *arg, int len, ptm_event_t *ev)
{
    char abuf[INET6_ADDRSTRLEN + 1];
    struct ptm_quagga_msg *msg = (struct ptm_quagga_msg *)arg;

    ev->module = QUAGGA_MODULE;

    if (len < sizeof(struct sockaddr_in)) {
        return -1;
    }

    inet_ntop(msg->lin.sin_family, (const void *)&msg->lin.sin_addr,
              abuf, sizeof(abuf));

    switch(ntohs(msg->lin.sin_family)) {
    case AF_INET6:
        ev->rv6addr = strdup(abuf);
        break;
    case AF_INET:
        ev->rv4addr = strdup(abuf);
        break;
    default:
        ERRLOG("Quagga socket sent bad address family\n");
        break;
    }
    ev->liface = strdup(msg->lport);

    /* make event coherent for fields that are not indicated */
    ev->riface = NULL;
    ev->rmac = NULL; /* this needs to be pulled out */
    return (0);
}

int
ptm_process_quagga_client (int in_fd,
                           ptm_sockevent_e se, void *udata)
{
    int end = 0;
    char qmsg[REPLY_BUFFER];
    int recved = 0;

    if (PTM_GET_STATE(ptm_quagga.gbl) != PTM_RUNNING) {
        return (-1);
    }

    assert(in_fd == PTM_MODULE_FD(ptm_quagga.gbl, QUAGGA_MODULE, 0));



    /* parse reply */
    while (!end) {
        int len = 0;

        len = recv(PTM_MODULE_FD(ptm_quagga.gbl, QUAGGA_MODULE, 0), &qmsg,
                   (REPLY_BUFFER - len), MSG_DONTWAIT);
        if (len < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                ERRLOG("%s: recvmsg error (%s), breaking\n", __FUNCTION__,
                        strerror(errno));
                break;
            }
            else {
                ERRLOG("%s: recvmsg error (%s), continuing\n", __FUNCTION__,
                        strerror(errno));
                continue;
            }
        }

        if (len == 0) {
            printf("%s: recvmsg EOF\n", __FUNCTION__);
            ptm_fd_cleanup(ptm_quagga.fd);
            PTM_MODULE_SET_FD(ptm_quagga.gbl,
                    ptm_quagga.fd_server, QUAGGA_MODULE, 0);
            close(ptm_quagga.fd);
            break;
        }

        recved += len;

        if (len) {
            _extract_event(qmsg, len, &ptm_quagga.event);
            ptm_module_handle_event_cb(&ptm_quagga.event);
            ptm_event_cleanup(&ptm_quagga.event);
            break;
        }
    } /* end while */

    return (0);
}

int
ptm_process_quagga (int in_fd,
                    ptm_sockevent_e se, void *udata)
{
    int ret = 0;

    assert(in_fd == PTM_MODULE_FD(ptm_quagga.gbl, QUAGGA_MODULE, 0));

    if (in_fd == ptm_quagga.fd_server) {

        int length, out_fd, rc;
        socklen_t peer_addr_size = sizeof(struct sockaddr_un);
        struct sockaddr_un peer_addr;


        out_fd = accept(in_fd, (struct sockaddr *) &peer_addr,
                        &peer_addr_size);
        if (out_fd < 0) {
            perror("accept() failed");
            ret = out_fd;
            goto out;
        }

        length = sizeof(struct ptm_quagga_msg);
        rc = setsockopt(out_fd, SOL_SOCKET, SO_RCVLOWAT,
                        (char *)&length, sizeof(length));
        if (rc < 0) {
            perror("setsockopt() failed");
            ret = out_fd;
            goto out;
        }

        ptm_quagga.fd = out_fd;
        PTM_MODULE_SET_FD(ptm_quagga.gbl, ptm_quagga.fd, QUAGGA_MODULE, 0);
    } else if (in_fd == ptm_quagga.fd) {
        ret = ptm_process_quagga_client(in_fd, se, udata);
    } else {
        ERRLOG("Connection error from quagga\n");
        ret = -1;
    }
out :
    return (ret);
}

int
ptm_init_quagga (ptm_globals_t *g)
{

    ptm_quagga.gbl = g;
    ptm_quagga.pid = getpid();

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, QUAGGA_MODULE);
    PTM_MODULE_PROCESSCB(g, QUAGGA_MODULE) = ptm_process_quagga;

    /*
     * prepare unix domain socket for quagga comm
     */
    ptm_quagga_connect(&ptm_quagga.fd_server, DIR_SERVER);
    PTM_MODULE_SET_FD(g, ptm_quagga.fd_server, QUAGGA_MODULE, 0);
    DLOG("Created quagga socket\n");

    //_send_quagga_request(QUAGGA_INIT);
    //ptm_process_quagga(mod->fd, SOCKEVENT_READ, NULL);

    PTM_MODULE_SET_STATE(g, QUAGGA_MODULE, MOD_STATE_INITIALIZED);

    return (0);
}
