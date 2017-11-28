/* Copyright 2011 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2015,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

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
