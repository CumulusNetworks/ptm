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

#ifndef __PTMUTIL__H
#define __PTMUTIL__H

extern void
ptm_util_extract_ipv6_pkt_info(void *pi6, int *ifindex,
                                struct in6_addr *ip6_addr);

#endif /* __PTMUTIL__H */
