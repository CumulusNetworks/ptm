/* Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _PTM_LLDP_H_
#define _PTM_LLDP_H_

#include "hash/uthash.h"

typedef enum {
  PORT_DESCRIPTION,
  PORTID_IFNAME,
} lldp_match_type_t;

typedef struct _lldp_parms_s {
    lldp_match_type_t match_type;
    int match_hostname;
} lldp_parms_t;

typedef struct _lldp_parm_hash_s {
    char port_name[MAXNAMELEN+1];
    lldp_parms_t parms;
    UT_hash_handle ph;      /* use port as key */
} lldp_parms_hash_t;

typedef struct _match_type_list {
    char *str;
    lldp_match_type_t type;
} match_type_list;

typedef struct _match_hostname_list {
    char *str;
    int type;
} match_hostname_list;

typedef struct _lldp_parms_key_s {
    char *key;
    int (*key_cb)(lldp_parms_t *, char *);
} lldp_parms_key_t;

typedef struct _lldp_cache_port {
    char liface[MAXNAMELEN+1];
    void *iface;
    ptm_event_t *ev;
    UT_hash_handle pch;
} lldp_cache_port;

typedef struct _lldp_port {
    char liface[MAXNAMELEN+1];
    char sys_name[MAXNAMELEN+1];
    char port_name[MAXNAMELEN+1];
    char port_descr[MAXNAMELEN+1];
    char mac_addr[MAC_ADDR_SIZE];
    char ipv4_addr[INET_ADDRSTRLEN+1];
    char ipv6_addr[INET6_ADDRSTRLEN+1];
    char chassis_id[MAC_ADDR_SIZE];
    time_t last_change_time;
    lldp_match_type_t match_type;
    int match_hostname;
    UT_hash_handle ph; /* use port as key */
} lldp_port;

int ptm_init_lldp(ptm_globals_t *g);
void ptm_shutdown_lldp();
void *ptm_lldp_get_next_sess_iter(void *);

#endif
