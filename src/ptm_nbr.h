/* Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _PTM_NBR_H_
#define _PTM_NBR_H_

#include "linux/if_ether.h"
#include "hash/uthash.h"
#include "ptm_ipaddr.h"

#define MAC_STR_SZ 20

typedef struct nbr_key_s {
    char port_name[MAXNAMELEN+1];       /* local port */
    char addr[INET6_ADDRSTRLEN+1];
} nbr_key_t;

typedef struct pri_nbr_key_s {
    char port_name[MAXNAMELEN+1];       /* local port */
    int afi;
} pri_nbr_key_t;

typedef struct nbr_hash_s {
    int  afi;
    bool is_primary;
    pri_nbr_key_t pri_key;
    nbr_key_t key;
    UT_hash_handle aph;                 /* use remote addr+port as key */
    UT_hash_handle afph;                /* use afi+port as key */
    char mac[MAC_STR_SZ];
} nbr_hash_t;

int ptm_init_nbr(ptm_globals_t *g);
bool ptm_nbr_is_addr_primary(char *, char *);

#endif
