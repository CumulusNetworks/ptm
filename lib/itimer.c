/* Copyright 2013 Cumulus Networks Inc.  All rights reserved. */
/* See License file for licenese. */

#include "cumulus.h"

#include "itimer.h"

bool itimer;

void itimer_init(void)
{
    itimer = getenv("ITIMER") != NULL;
}

void itimer_log_interval(itimer_t *timer, const char *msg)
{
    itimer_t _tmp = itimer_get_us();

    LOG("ITIMER: %s took %"PRIitimer_t" usecs\n", msg, _tmp - *timer);
    *timer = _tmp;
}

itimer_t proftimer_usec[NUMPROFTIMER];
itimer_t proftimer_tmp [NUMPROFTIMER];

void proftimer_init(void)
{
    int i;

    if (!itimer) {
	return;
    }
    for (i = 0; i < NUMPROFTIMER; i++) {
	proftimer_usec[i] = 0;
    }
}

void proftimer_log(void)
{
    int i;

    if (!itimer) {
	return;
    }
    for (i = 0; i < NUMPROFTIMER; i++) {
	if (proftimer_usec[i] != 0) {
	     LOG("proftimer : %d : %"PRIitimer_t"\n", i, proftimer_usec[i]);
	}
    }
}
