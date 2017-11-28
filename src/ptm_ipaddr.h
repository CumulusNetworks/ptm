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

#ifndef __PTMIPADDR__H
#define __PTMIPADDR__H

typedef struct _ptm_ipaddr {
  uint8_t family;
  union {
      struct in_addr ip4_addr;
      struct in6_addr ip6_addr;
  };
} ptm_ipaddr;


/* Prototypes */
extern const char *
ptm_ipaddr_net2str(ptm_ipaddr *ipaddr, char *str);
extern int
ptm_ipaddr_str2net (const char *str, ptm_ipaddr *ipaddr);
extern int
ptm_ipaddr_cmp(ptm_ipaddr *ipaddr1, ptm_ipaddr *ipaddr2);
extern int
ptm_ipaddr_get_ip_type (const char *str);
extern int
ptm_ipaddr_is_ipv6_link_local(const char *str);

#endif /* __PTMIPADDR__H */
