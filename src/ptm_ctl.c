/*********************************************************************
 * Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * ptm_ctl.[ch]: create a unix socket and listen on it for requests.
 */

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "ptm_event.h"
#include "log.h"
#include "ptm_lib.h"
#include "ptm_conf.h"
#include "ptm_ctl.h"
#include <sys/stat.h>

/* listen() call's backlog */
#define MAX_CONNECTIONS 10
#define MAX_CLIENTS     16
const char  PTMD_CTL_SOCKET[] = "\0/var/run/ptmd.socket";


/**
 * Global structure (private to this file) for bookkeeping - init params,
 * input params, statistics, and such.
 */
typedef struct {
    ptm_globals_t  *gbl;
    ptm_event_t    event;
    ptm_client_t   *clients[FD_SETSIZE];
    int            num_clients;
    TAILQ_HEAD(, _ptm_client_t_) client_list;
} ptm_ctl_globals_t;

ptm_ctl_globals_t ptm_ctl;

static void
_cleanup_client (int fd)
{
    ptm_client_t *client;
    ptm_client_buf_t *client_buf;

    if (ptm_ctl.clients[fd]) {
        client = ptm_ctl.clients[fd];
        ptm_ctl.clients[fd] = NULL;
        TAILQ_REMOVE(&(ptm_ctl.client_list), client, next);
        while((client_buf = TAILQ_FIRST(&(client->pend_buflist))) != NULL) {
            TAILQ_REMOVE(&(client->pend_buflist), client_buf, next);
            free(client_buf);
        }
        free(client);
        ptm_ctl.num_clients--;

        INFOLOG("Free client connection fd[%d] tot[%d]\n", fd,
                ptm_ctl.num_clients);
    }
    ptm_fd_cleanup(fd);
}

static int
_accept_client (ptm_sockevent_e se)
{
    ptm_globals_t *g = ptm_ctl.gbl;
    ptm_client_t *client;
    int newfd;

    /* Accept all incoming connections that are queued up on the socket */
    do {
        newfd = accept(PTM_MODULE_FD(g, CTL_MODULE, 0), NULL, NULL);
        if (newfd < 0) {
            if (errno != EWOULDBLOCK) {
                ERRLOG("%s: accept() failed (%s)\n", __FUNCTION__,
                    strerror(errno));
                return (-1);
            }
            break;
        }

        if (ptm_ctl.num_clients == MAX_CLIENTS) {
            ERRLOG("%s: Max clients connected (%d) - ignore accept\n",
                   __FUNCTION__, ptm_ctl.num_clients);
            _cleanup_client(newfd);
            return (-1);
        }

        /* Set the fd to non-blocking mode. */
        fcntl(newfd, F_SETFL, O_NONBLOCK);

        /* Add the fd to the main event loop so we start watching for events */
        ptm_fd_add(newfd);

        assert(ptm_ctl.clients[newfd] == NULL);
        client = malloc(sizeof(ptm_client_t));
        if (client == NULL) {
            ERRLOG("malloc error for client structure\n");
            _cleanup_client(newfd);
            return (-1);
        }
        memset(client, 0, sizeof(ptm_client_t));
        client->fd = newfd;
        ptm_ctl.clients[newfd] = client;
        TAILQ_INIT(&(client->pend_buflist));
        client->pend_numbufs = 0;
        client->curr_buflen = 0;
        TAILQ_INSERT_TAIL(&(ptm_ctl.client_list), client, next);
        ptm_ctl.num_clients++;

        INFOLOG("New client connection fd[%d] tot[%d]\n", newfd,
                ptm_ctl.num_clients);

    } while (newfd != -1);
    return (0);
}

static int
_process_client (int in_fd,
                 ptm_sockevent_e se)
{
    ptm_client_t *client;
    int close_conn = 0;
    int rc = 0;

    if(ptm_ctl.clients[in_fd] == NULL) {
        ERRLOG("%s: no client for this fd=%d\n", __FUNCTION__, in_fd);
        return -1;
    }

    client = ptm_ctl.clients[in_fd];

    if (se == SOCKEVENT_WRITE) {
        rc = ptm_ctl_send(client, NULL, 0);
        return (rc);
    }

    rc = ptm_lib_process_msg(ptm_ctl.gbl->ptmlib_hdl, in_fd,
                             client->inbuf, sizeof(client->inbuf),
                             client);
    if (rc < 0)
        close_conn = 1;

    if (PTM_CLIENT_GET_FLAGS(client) & PTM_CLIENT_MARK_FOR_DELETION)
        close_conn = 1;

    if (close_conn)
        _cleanup_client(in_fd);

    return (rc);
}

int
ptm_process_ctl (int in_fd,
                 ptm_sockevent_e se,
                 void *udata)
{
    ptm_globals_t *g = ptm_ctl.gbl;

    /*
     * Is it coming on the listen socket?
     */
    if (in_fd == PTM_MODULE_FD(g, CTL_MODULE, 0)) {
        _accept_client(se);
    } else {
        _process_client(in_fd, se);
    }
    return (0);
}

/**
 * Create a new listening Unix socket for control protocol.
 *
 * @param name The name of the Unix socket.
 * @return The socket when successful, -1 otherwise.
 */
int
ptm_init_ctl (ptm_globals_t *g)
{
    struct sockaddr_un su;
    int fd, rc;
    int flags = 0;

    ptm_ctl.gbl = g;
    TAILQ_INIT(&(ptm_ctl.client_list));

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, CTL_MODULE);
    PTM_MODULE_PROCESSCB(g, CTL_MODULE) = ptm_process_ctl;
    g->ptmlib_hdl = ptm_lib_register("ptm",
                        ptm_conf_process_client_cmd, NULL, NULL);

    flags = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
    if ((fd = socket(AF_UNIX, flags, 0)) == -1) {
        return (-1);
    }

    PTM_MODULE_SET_FD(g, fd, CTL_MODULE, 0);

    /* Using abstract namespace socket */
    memset(&su, 0, sizeof(su));
    su.sun_family = AF_UNIX;
    memcpy(su.sun_path, PTMD_CTL_SOCKET, sizeof(PTMD_CTL_SOCKET));

    if (bind(fd, (struct sockaddr *)&su,
             sizeof(su.sun_family)+sizeof(PTMD_CTL_SOCKET)-1) == -1) {
        rc = errno; close(fd); errno = rc;
        ERRLOG("bind error, err=%s\n", strerror(errno));
        return (-1);
    }

    if (listen(fd, MAX_CONNECTIONS) == -1) {
        rc = errno; close(fd); errno = rc;
        ERRLOG("cannot listen to control socket %s\n", PTMD_CTL_SOCKET);
        return (-1);
    }

    PTM_MODULE_SET_STATE(g, CTL_MODULE, MOD_STATE_INITIALIZED);

    return (0);
}

int
ptm_ctl_send (ptm_client_t *client,
              char *buf,
              int buflen)
{
    ptm_globals_t *g = ptm_ctl.gbl;
    ptm_client_buf_t *client_buf;
    int rc = 0;
    int len = 0;

    if (!client ||
        (PTM_CLIENT_GET_FLAGS(client) & PTM_CLIENT_MARK_FOR_DELETION)) {
        return (-1);
    }

    /**
     * If there is some data in the outbuf, the last send was unsuccessful
     * (e.g. flow control), so just queue up new ones. We will re-transmit
     * when we get called through select() that socket is available for
     * write. In that case, buf would be NULL and buflen = 0.
     */
    if (client->curr_buflen && buflen) {
        /* we have pending buffers - queue up new requests */
        client_buf = (ptm_client_buf_t *)malloc(sizeof(ptm_client_buf_t));
        if (client_buf) {
            strcpy(client_buf->outbuf, buf);
            client_buf->outbuf_len = buflen;
            TAILQ_INSERT_TAIL(&(client->pend_buflist), client_buf, next);
            client->pend_numbufs++;
            DLOG("%s: Queueing pending buffer send [#%d]\n",
                 __func__, client->pend_numbufs);
            return (0);
        }
        return (-1);
    }

    if (buflen) {
        memcpy(client->outbuf, buf, buflen);
        client->curr_buflen = buflen;
        client->curr_outbuf = client->outbuf;
    }

    len = client->curr_buflen;
    while (len != 0) {
        rc = send(client->fd, client->curr_outbuf, len, MSG_NOSIGNAL);
        if (rc < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                DLOG("  send() flow control(%s)\n", strerror(errno));
                FD_SET(client->fd, &g->writeset);
                if (client->fd > g->maxfd) {
                    g->maxfd = client->fd;
                }
            } else {
                /* let the caller clean up the client structure */
                ERRLOG("  send() failed(%s)\n", strerror(errno));
                PTM_CLIENT_SET_FLAGS(client, PTM_CLIENT_MARK_FOR_DELETION);
                return (rc);
            }
            break;
        }
        len -= rc;
        client->curr_outbuf += rc;
        /* if we have finished sending one buffer - check pending */
        if ((len == 0) && (!TAILQ_EMPTY(&(client->pend_buflist)))) {
            client_buf = TAILQ_FIRST(&(client->pend_buflist));
            memcpy(client->outbuf, client_buf->outbuf, client_buf->outbuf_len);
            len = client->curr_buflen = client_buf->outbuf_len;
            client->curr_outbuf = client->outbuf;
            TAILQ_REMOVE(&(client->pend_buflist), client_buf, next);
            free(client_buf);
            client->pend_numbufs--;
        }
    }

    client->curr_buflen = len;
    if (len == 0) {
        client->curr_outbuf = NULL;
        FD_CLR(client->fd, &g->writeset);
    }
    return (rc);
}

ptm_client_t *
ptm_client_iter ()
{
    return (TAILQ_FIRST(&(ptm_ctl.client_list)));
}

ptm_client_t *
ptm_client_iter_next (ptm_client_t *curr)
{
    return (TAILQ_NEXT(curr, next));
}


ptm_client_t *
ptm_client_safe_iter (ptm_client_t **saved)
{
    ptm_client_t *clnt;

    if (!saved) {
        return (NULL);
    }
    clnt = TAILQ_FIRST(&(ptm_ctl.client_list));
    if (clnt != NULL) {
        *saved = TAILQ_NEXT(clnt, next);
    }
    return (clnt);
}

ptm_client_t *
ptm_client_safe_iter_next (ptm_client_t **saved)
{
    ptm_client_t *clnt;

    if (!saved) {
        return (NULL);
    }
    clnt = *saved;
    if (clnt != NULL) {
        *saved = TAILQ_NEXT(clnt, next);
    }
    return (clnt);
}

void
ptm_client_delete (ptm_client_t *client)
{
    _cleanup_client(client->fd);
}
