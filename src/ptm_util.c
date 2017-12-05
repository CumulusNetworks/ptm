/*********************************************************************
 * Copyright 2015 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * ptm_util.[ch]: Utilitity functions
 *
 */

#include <stdio.h>
#include <linux/ipv6.h>
#include <linux/in6.h>

void
ptm_util_extract_ipv6_pkt_info(void *data, int *ifindex,
                                struct in6_addr *ip6_addr)
{
    struct in6_pktinfo *pi6 = (struct in6_pktinfo *)data;

    *ip6_addr = pi6->ipi6_addr;
    *ifindex = pi6->ipi6_ifindex;
}
