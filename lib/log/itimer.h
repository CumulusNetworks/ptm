/* Copyright 2011 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2015,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _ITIMER_H_
#define _ITIMER_H_

#include <sys/time.h>
#include <stdlib.h>

#include "log.h"

typedef uint64_t itimer_t;
#define PRIitimer_t PRIu64

static inline itimer_t itimer_get_us(void) {
    struct timeval tv;

    gettimeofday(&tv, 0);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}

void itimer_init(void);
void itimer_log_interval(itimer_t *timer, const char *msg);

extern bool itimer;

#define START_ITIMER(timer)                                             \
    if (itimer) { timer = itimer_get_us(); } else
#define PRINT_INTERVAL(timer, msg)                                      \
    if (itimer) { itimer_log_interval(&timer, msg); } else


#define NUMPROFTIMER 10
extern itimer_t proftimer_usec[NUMPROFTIMER];
extern itimer_t proftimer_tmp [NUMPROFTIMER];

void proftimer_init(void);
void proftimer_log(void);

#define INIT_PROFTIMER() \
    if (itimer) { proftimer_init(); } else 

#define START_PROFTIMER(which) \
    if (itimer) { proftimer_tmp[which] = itimer_get_us(); } else

#define ACCUM_PROFTIMER(which) \
    if (itimer) { proftimer_usec[which] += (itimer_get_us() - proftimer_tmp[which]); } else

#define LOG_PROFTIMER()	\
    if (itimer) { proftimer_log(); } else 


#endif
