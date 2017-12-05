/*********************************************************************
 * Copyright 2015 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * ptm_ipaddr.[ch]: Wrapper functions for IPv4/IPv6 address conversions.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ptm_ipaddr.h"

const char *
ptm_ipaddr_net2str(ptm_ipaddr *ipaddr, char *str)
{
    switch (ipaddr->family)
    {
    case AF_INET:
        inet_ntop (AF_INET, &ipaddr->ip4_addr, str, INET_ADDRSTRLEN);
        break;
    case AF_INET6:
        inet_ntop (AF_INET6, &ipaddr->ip6_addr, str, INET6_ADDRSTRLEN);
        break;
    default:
        strcpy(str, "N/A");
    }
    return str;
}

int
ptm_ipaddr_str2net (const char *str, ptm_ipaddr *ipaddr)
{
    int ret;

    memset (ipaddr, 0, sizeof (ptm_ipaddr));

    ret = inet_pton (AF_INET, str, &ipaddr->ip4_addr);
    /* Valid IPv4 address format */
    if (ret > 0)
    {
        ipaddr->family = AF_INET;
        return 0;
    }

    ret = inet_pton (AF_INET6, str, &ipaddr->ip6_addr);
    /* Valid IPv6 address format */
    if (ret > 0)
    {
        ipaddr->family = AF_INET6;
        return 0;
    }

    return -1;
}

int
ptm_ipaddr_cmp(ptm_ipaddr *ipaddr1, ptm_ipaddr *ipaddr2)
{
    if (ipaddr1->family != ipaddr2->family) {
        return -1;
    }

    switch (ipaddr1->family)
    {
    case AF_INET:
        if (ipaddr1->ip4_addr.s_addr == ipaddr2->ip4_addr.s_addr) {
            return 0;
        } else {
            return -1;
        }
    case AF_INET6:
        if (memcmp (&ipaddr1->ip6_addr, &ipaddr2->ip6_addr,
                sizeof(struct in6_addr)) == 0)
            return 0;
        else
            return -1;
    default:
        return -1;
    }
}

int
ptm_ipaddr_get_ip_type (const char *str)
{
    int ret;
    ptm_ipaddr ipaddr;

    ret = inet_pton (AF_INET, str, &ipaddr.ip4_addr);
    /* Valid IPv4 address format */
    if (ret > 0)
    {
        return AF_INET;
    }

    ret = inet_pton (AF_INET6, str, &ipaddr.ip6_addr);
    /* Valid IPv6 address format */
    if (ret > 0)
    {
        return AF_INET6;
    }

    return -1;
}

int
ptm_ipaddr_is_ipv6_link_local(const char *str)
{
    int ret;
    ptm_ipaddr ipaddr;

    if (!str)
        return 0;

    ret = inet_pton (AF_INET6, str, &ipaddr.ip6_addr);
    /* Valid IPv6 address format */
    if (ret > 0) {
        return IN6_IS_ADDR_LINKLOCAL(&ipaddr.ip6_addr);
    }

    return 0;
}
