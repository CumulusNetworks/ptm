/* Copyright 2013 Cumulus Networks, LLC.  All rights reserved. */

#ifndef _PTM_CTL_H_
#define _PTM_CTL_H_

#include <sys/queue.h>

extern const char PTMD_CTL_SOCKET[];
#define CTL_MESSAGE_SIZE 4096

#define PTM_CLIENT_FLAGS_DETAIL_MODE    (1 << 0)

/**
 * Each connection made to the ptmd (server) unix socket is represented
 * in a ptm_client_t structure.
 */
struct _ptm_client_t_ {
    TAILQ_ENTRY(_ptm_client_t_) next;
    int                         fd;
    char                        inbuf[CTL_MESSAGE_SIZE];
    int                         inbuf_len;
    char                        outbuf[CTL_MESSAGE_SIZE];
    int                         outbuf_len;
    char                        *pendingbuf;
    uint32_t                    flags;
};

#define PTM_SET_CLIENT_DETAIL_MODE(client) \
    (client)->flags |= PTM_CLIENT_FLAGS_DETAIL_MODE

#define PTM_RESET_CLIENT_DETAIL_MODE(client) \
    (client)->flags &= ~(PTM_CLIENT_FLAGS_DETAIL_MODE)

#define PTM_CLIENT_DETAIL_MODE(client) \
    ((client)->flags & PTM_CLIENT_FLAGS_DETAIL_MODE)

/**
 * Hook up for ptm_event.c. Init routine to set up the control socket etc.
 */
int ptm_init_ctl(ptm_globals_t *g);

/**
 * Hook up for ptm_event.c. Routine to process any time there is an incoming
 * client connection or data on an existing connection...
 */
int ptm_process_ctl(int, ptm_sockevent_e se, void *);

/**
 * Use this routine to send some data to a client.
 *
 * @param client: the client to send the data to
 * @param buf: the data
 * @param blen: data length
 */
int ptm_ctl_send(ptm_client_t *client, char *buf, int blen);

/**
 * Utility routines to iterate through the clients (note: read-only).
 * Useful if PTM layer wants to send some notification to all clients
 * uniformly.
 */
ptm_client_t *ptm_client_iter();
ptm_client_t *ptm_client_iter_next(ptm_client_t *);

ptm_client_t *ptm_client_safe_iter(ptm_client_t **);
ptm_client_t *ptm_client_safe_iter_next(ptm_client_t **);

#endif
