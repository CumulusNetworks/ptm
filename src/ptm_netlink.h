/* Copyright 2016 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _PTM_NETLINK_H_
#define _PTM_NETLINK_H_

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include "hash/uthash.h"
#include "ptm_ipaddr.h"

int ptm_init_nl (ptm_globals_t *g);

#endif
