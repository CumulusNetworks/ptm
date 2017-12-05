/* Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _PTM_CTL_H_
#define _PTM_CTL_H_

#include <sys/queue.h>

extern const char PTMD_CTL_SOCKET[];

typedef struct _ptm_client_buf_t_ {
    TAILQ_ENTRY(_ptm_client_buf_t_) next;
    char                        outbuf[CTL_MSG_SZ];
    int                         outbuf_len;
} ptm_client_buf_t;

/**
 * Each connection made to the ptmd (server) unix socket is represented
 * in a ptm_client_t structure.
 */
struct _ptm_client_t_ {
    TAILQ_ENTRY(_ptm_client_t_) next;
    int                         fd;
    char                        inbuf[CTL_MSG_SZ];
    int                         inbuf_len;
    char                        outbuf[CTL_MSG_SZ];
    int                         curr_buflen;
    char                        *curr_outbuf;
    TAILQ_HEAD(, _ptm_client_buf_t_) pend_buflist;
    int                         pend_numbufs;
    uint32_t                    flags;
};

/* flags for client */
#define PTM_CLIENT_MARK_FOR_DELETION    0x01
#define PTM_CLIENT_REQUEST_RECD         0x02

#define PTM_CLIENT_SET_FLAGS(_c, _f) ((_c)->flags |= (_f))
#define PTM_CLIENT_CLR_FLAGS(_c, _f) ((_c)->flags &= ~(_f))
#define PTM_CLIENT_GET_FLAGS(_c) ((_c)->flags)

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
void          ptm_client_delete (ptm_client_t *client);

#endif
