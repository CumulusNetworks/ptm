/* Copyright 2013 Cumulus Networks, LLC.  All rights reserved. */

#ifndef _PTM_LLDP_H_
#define _PTM_LLDP_H_

int ptm_process_lldp(int, ptm_sockevent_e, void *);
int ptm_init_lldp(ptm_globals_t *g);
void ptm_finish_lldp(void);
int ptm_populate_lldp(void);

#endif
