/* Copyright 2013 Cumulus Networks, Inc.  All rights reserved. */

#ifndef _PTM_LLDP_H_
#define _PTM_LLDP_H_

#include "hash/uthash.h"

typedef enum {
  PORT_DESCRIPTION,
  PORTID_IFNAME,
} lldp_match_type_t;

typedef struct _lldp_parms_s {
    lldp_match_type_t match_type;
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

typedef struct _lldp_parms_key_s {
    char *key;
    int (*key_cb)(lldp_parms_t *, char *);
} lldp_parms_key_t;

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
    UT_hash_handle ph; /* use port as key */
} lldp_port;

int ptm_init_lldp(ptm_globals_t *g);
void ptm_shutdown_lldp();

#endif
