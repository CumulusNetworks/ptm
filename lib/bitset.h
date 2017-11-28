/* Copyright 2011 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2015,2016,2017 Cumulus Networks, Inc. All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _BITSET_H_
#define _BITSET_H_

typedef struct {
    int size_bits;
    uint8_t *bits;
} bitset_t;

static inline bitset_t bitset_alloc(int size_bits) {
    bitset_t ret;

    ret.size_bits = size_bits;
    ret.bits = calloc((size_bits + 7) / 8, 1);
    return ret;
}

static inline void bitset_free(bitset_t bs) {
    free(bs.bits);
}

static inline void bitset_set(bitset_t bs, int offset) {
    bs.bits[offset / 8] |= 1 << (offset % 8);
}

static inline void bitset_unset(bitset_t bs, int offset) {
    bs.bits[offset / 8] &= ~(1 << (offset % 8));
}

static inline bool bitset_get(bitset_t bs, int offset) {
    return !!(bs.bits[offset / 8] & (1 << (offset % 8)));
}

static inline void bitset_clear(bitset_t bs) {
    memset(bs.bits, '\0', (bs.size_bits + 7) / 8);
}

static inline int bitset_get_first(bitset_t bs) {
    uint8_t p[16] = {0, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0};
    int i = 0, bn = 0;
    do {
        if (bs.bits[i]) {
            bn = (bs.bits[i] & 0x0f)?p[bs.bits[i] & 0x0f]
                                    :p[bs.bits[i] >> 4] + 4;
            return ((i << 3) + bn);
        }
    } while ((++i << 3) < bs.size_bits);
    return -1;
}

#endif
