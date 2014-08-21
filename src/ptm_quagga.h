/* Copyright 2013 Cumulus Networks, Inc.  All rights reserved. */

#ifndef _PTM_QUAGGA_H_
#define _PTM_QUAGGA_H_

int ptm_init_quagga(ptm_globals_t *g);
int ptm_process_quagga(int, ptm_sockevent_e, void *);

#endif
