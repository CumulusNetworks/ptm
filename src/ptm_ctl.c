/*********************************************************************
 * Copyright 2013 Cumulus Networks, Inc.  All rights reserved.
 *
 * ptm_ctl.[ch]: create a unix socket and listen on it for requests.
 */

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "ptm_event.h"
#include "log.h"
#include "ptm_ctl.h"
#include <sys/stat.h>

/* listen() call's backlog */
#define MAX_CONNECTIONS 10
const char  PTMD_CTL_SOCKET[] = "\0/var/run/ptmd.socket";

/**
 * Global structure (private to this file) for bookkeeping - init params,
 * input params, statistics, and such.
 */
typedef struct {
    ptm_globals_t  *gbl;
    ptm_event_t    event;
    ptm_client_t   *clients[FD_SETSIZE];
    TAILQ_HEAD(, _ptm_client_t_) client_list;
} ptm_ctl_globals_t;

ptm_ctl_globals_t ptm_ctl;

static void
_cleanup_client (int fd)
{
    ptm_client_t *client;

    if (ptm_ctl.clients[fd]) {
        client = ptm_ctl.clients[fd];
        ptm_ctl.clients[fd] = NULL;
        TAILQ_REMOVE(&(ptm_ctl.client_list), client, next);
        free(client);
    }
    ptm_fd_cleanup(fd);
}

static int
_extract_event (ptm_event_t *ev,
                ptm_client_t *client,
                ptm_event_e type)
{
    if (!ev || !client) {
        return (1);
    }
    ev->type = type;
    ev->module = CTL_MODULE;
    ev->client = client;
    return (0);
}

static int
_accept_client (ptm_sockevent_e se)
{
    ptm_globals_t *g = ptm_ctl.gbl;
    ptm_client_t *client;
    int newfd;

    /* Accept all incoming connections that are queued up on the socket */
    do {
        newfd = accept(PTM_MODULE_FD(g, CTL_MODULE), NULL, NULL);
        if (newfd < 0) {
            if (errno != EWOULDBLOCK) {
                LOG("accept() failed (%s)\n", strerror(errno));
                return (1);
            }
            break;
        }

        LOG("  New incoming connection - %d\n", newfd);

        /* Set the fd to non-blocking mode. */
        fcntl(newfd, F_SETFL, O_NONBLOCK);

        /* Add the fd to the main event loop so we start watching for events */
        ptm_fd_add(newfd);

        assert(ptm_ctl.clients[newfd] == NULL);
        client = malloc(sizeof(ptm_client_t));
        if (client == NULL) {
            ERRLOG("malloc error for client structure\n");
            _cleanup_client(newfd);
            return (1);
        }
        memset(client, 0, sizeof(client));
        client->fd = newfd;
        ptm_ctl.clients[newfd] = client;
        TAILQ_INSERT_TAIL(&(ptm_ctl.client_list), client, next);
        if (PTM_MODULE_EVENTCB(ptm_ctl.gbl, CTL_MODULE)) {
            _extract_event(&ptm_ctl.event, client, EVENT_ADD);
            PTM_MODULE_EVENTCB(ptm_ctl.gbl, CTL_MODULE)(&ptm_ctl.event);
        }
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

    assert(ptm_ctl.clients[in_fd] != NULL);
    client = ptm_ctl.clients[in_fd];

    if (se == SOCKEVENT_WRITE) {
        DLOG("_process_client: SOCKEVENT_WRITE\n");
        rc = ptm_ctl_send(client, NULL, 0);
        return (rc);
    }

    do {
        rc = recv(in_fd, client->inbuf, CTL_MESSAGE_SIZE, 0);
        if (rc < 0) {
            if (errno != EWOULDBLOCK) {
                LOG("  recv() failed (%s)\n", strerror(errno));
                close_conn = 1;
            }
            break;
        }
        if (rc == 0) {
            LOG("  Connection closed\n");
            close_conn = 1;
            break;
        }

        client->inbuf_len = rc;
        DLOG("  %d bytes received\n", client->inbuf_len);
        if (PTM_MODULE_EVENTCB(ptm_ctl.gbl, CTL_MODULE)) {
            _extract_event(&ptm_ctl.event, client, EVENT_UPD);
            PTM_MODULE_EVENTCB(ptm_ctl.gbl, CTL_MODULE)(&ptm_ctl.event);
        }
    } while (1);

    if (close_conn) {
        _cleanup_client(in_fd);
    }
    return (rc);
}

int
ptm_process_ctl (int in_fd,
                 ptm_sockevent_e se,
                 void *udata)
{
    ptm_globals_t *g = ptm_ctl.gbl;

    LOG("%s\n", __FUNCTION__);

    /*
     * Is it coming on the listen socket?
     */
    if (in_fd == PTM_MODULE_FD(g, CTL_MODULE)) {
        DLOG("  Listening socket is readable\n");
        _accept_client(se);
    } else {
        DLOG("  Descriptor %d is readable\n", in_fd);
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

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return (-1);
    }

    PTM_MODULE_SET_FD(g, fd, CTL_MODULE);
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Using abstract namespace socket */
    //unlink(name);
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
    return (0);
}

int
ptm_ctl_send (ptm_client_t *client,
              char *buf,
              int buflen)
{
    ptm_globals_t *g = ptm_ctl.gbl;
    int rc = 0;
    int len = 0;

    if (!client) {
        return (rc);
    }

    /**
     * If there is some data in the outbuf, the last send was unsuccessful
     * (e.g. flow control), so don't allow a new one. Exception is when we
     * get called through select() that socket is available for write. In
     * that case, buf would be NULL and buflen = 0.
     */
    if (client->outbuf_len && buflen) {
        errno = EWOULDBLOCK;
        return (-1);
    }

    if (buflen) {
        memcpy(client->outbuf, buf, buflen);
        client->outbuf_len = buflen;
        client->pendingbuf = client->outbuf;
    }

    len = client->outbuf_len;
    while (len != 0) {
        rc = send(client->fd, client->pendingbuf, len, MSG_NOSIGNAL);
        if (rc < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ERRLOG("  send() flow control(%s)\n", strerror(errno));
                FD_SET(client->fd, &g->writeset);
                if (client->fd > g->maxfd) {
                    g->maxfd = client->fd;
                }
            } else {
                ERRLOG("  send() failed(%s)\n", strerror(errno));
                _cleanup_client(client->fd);
                return (rc);
            }
            break;
        }
        len -= rc;
        client->pendingbuf += rc;
    }

    client->outbuf_len = len;
    if (len == 0) {
        client->pendingbuf = NULL;
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
