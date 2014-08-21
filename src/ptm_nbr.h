/* Copyright 2013 Cumulus Networks, Inc.  All rights reserved. */

#ifndef _PTM_NBR_H_
#define _PTM_NBR_H_

#include "hash/uthash.h"

typedef struct nbr_hash_s {
    char port_name[MAXNAMELEN+1];       /* local port */
    char ipv4_addr[INET_ADDRSTRLEN+1];
    char ipv6_addr[INET6_ADDRSTRLEN+1];
    ptm_event_t *event;                 /* copy of event */
    UT_hash_handle ah;                  /* use remote addr as key */
    UT_hash_handle ph;                  /* use port as key */
} nbr_hash_t;

int ptm_init_nbr(ptm_globals_t *g);
void ptm_nbr_get_event_by_port(char *port_name, ptm_event_t **event);
ptm_conf_port_t *ptm_nbr_get_port_from_addr(char *addr);

#endif
