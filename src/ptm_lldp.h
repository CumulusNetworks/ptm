/*********************************************************************
 * Copyright 2013 Cumulus Networks, Inc.  All rights reserved.
 *
 * ptm_lldp.[ch] contain the code that interacts with LLDPD over
 * the LLDPCTL interface, extract the required information,
 * translate them to ptm_event_t abstraction, and call the
 * registered callback for each notification.
 */
#ifndef _PTM_LLDP_H_
#define _PTM_LLDP_H_

int ptm_process_lldp(int, ptm_sockevent_e, void *);
int ptm_init_lldp(ptm_globals_t *g);
void ptm_finish_lldp(void);
int ptm_populate_lldp(void);

#endif
