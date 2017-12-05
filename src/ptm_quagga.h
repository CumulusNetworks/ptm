/* Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _PTM_QUAGGA_H_
#define _PTM_QUAGGA_H_

int ptm_init_quagga(ptm_globals_t *g);
int ptm_process_quagga(int, ptm_sockevent_e, void *);

#endif
