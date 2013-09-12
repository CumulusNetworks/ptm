/* Copyright 2013 Cumulus Networks Inc.  All rights reserved. */
/* See License file for licenese. */

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

#endif
