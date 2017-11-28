/* Copyright 2010 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2015,2016,2017 Cumulus Networks, Inc. All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _CUMULUS_H_
#define _CUMULUS_H_

#define _GNU_SOURCE
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#define TRUE true
#define FALSE false

typedef unsigned int uint_t;
typedef int int_t;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define min_t(type, x, y) ({                \
    type __min1 = (x);                      \
    type __min2 = (y);                      \
    __min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({                \
    type __max1 = (x);                      \
    type __max2 = (y);                      \
    __max1 > __max2 ? __max1: __max2; })

#define clamp_t(type, val, min, max) ({     \
    type __val = (val);                     \
    type __min = (min);                     \
    type __max = (max);                     \
    __val = __val < __min ? __min: __val;   \
    __val > __max ? __max: __val; })

#endif
