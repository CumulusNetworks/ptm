/* Copyright 2010 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2015,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <string.h>

enum log_level_e {
    LOG_LEVEL_ALWAYS = -1,
    LOG_LEVEL_CRIT = 0,
    LOG_LEVEL_ERR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_LAST
};

bool log_setup(const char **backends, int num_backends);
bool log_init(const char **backends, int num_backends);
void log_deinit(void);
enum log_level_e log_string_to_level(const char *str);
const char *log_level_to_string(enum log_level_e level);
bool log_reopen(void);
void log_backtrace(void);

/*
 * DLOG            Used for debug messages.  Information that is diagnostically 
 *                 helpful to people more than just developers (IT, sysadmins,
 *                 etc).
 * 
 * INFOLOG         Informational messages.  Generally useful information to log 
 *                 (service start/stop, configuration assumptions, etc).
 * 
 * WARNLOG         Warnings about problematic situations that do not, in 
 *                 themselves, create serious problems with the system, 
 *                 and are automatically recovered from.  May lead to 
 *                 ERRLOG/CRITLOG conditions down the road.
 * 
 * ERRLOG          Any error which is fatal to the operation but not the 
 *                 service or application (can't open a required file, missing 
 *                 data, etc). These errors will force user (administrator, 
 *                 or direct user) intervention.
 * 
 * CRITLOG         Critical conditions, often related to serious hardware 
 *                 or software failures.
 * 
 * LOG             Use for messages that should always appear, regardless
 *                 of current log level.
 */

#ifdef NDEBUG
#    define DLOG(...)
#else
#    define DLOG(fmt, ...) _DO_LOG(LOG_LEVEL_DEBUG, 1, fmt, ##__VA_ARGS__)
#endif
#define INFOLOG(fmt, ...) _DO_LOG(LOG_LEVEL_INFO, 1, fmt, ##__VA_ARGS__)
#define WARNLOG(fmt, ...) _DO_LOG(LOG_LEVEL_WARN, 1, "WARN " fmt, ##__VA_ARGS__)
#define ERRLOG(fmt, ...) _DO_LOG(LOG_LEVEL_ERR, 1, "ERR " fmt, ##__VA_ARGS__)
#define CRITLOG(fmt, ...) _DO_LOG(LOG_LEVEL_CRIT, 1, "CRIT " fmt, ##__VA_ARGS__)
#define LOG(fmt, ...) _DO_LOG(LOG_LEVEL_ALWAYS, 1, fmt, ##__VA_ARGS__)

#define __RELFILE ((strrchr(__FILE__, '/') ?: __FILE__ - 1) + 1)

#define MALLOC(sz) _cumulus_malloc(sz, __RELFILE, __LINE__)
#define CALLOC(nmemb, sz) _cumulus_calloc(nmemb, sz, __RELFILE, __LINE__)
#define REALLOC(ptr, sz) _cumulus_realloc(ptr, sz, __RELFILE, __LINE__)
#define STRDUP(s) _cumulus_strdup(s, __RELFILE, __LINE__)

/******************************************************************/

#define IF_LOG(lvl) if (_min_log_level >= (LOG_LEVEL_##lvl))

extern enum log_level_e _min_log_level;
#define _DO_LOG(lvl, on, fmt, ...)                                      \
    if ((_min_log_level >= (lvl)) && (on))                              \
        _log_log((lvl), "%s %s:%d " fmt, sizeof ("%s %s:%d " fmt),      \
                 _log_datestamp(), __RELFILE, __LINE__,                  \
                 ##__VA_ARGS__);                                        \
    else
const char *_log_datestamp(void);
void _log_log(enum log_level_e level, const char *fmt, int fmt_len, ...)
    __attribute__ ((format (printf, 2, 4)));

static inline void *_cumulus_malloc(size_t size, const char *f, int line) {
    void *ret = malloc(size);
    if (!ret) {
        CRITLOG("malloc returned NULL at %s:%d.\n", f, line);
        abort();
    }
    return ret;
}

static inline void *_cumulus_calloc(size_t nmemb, size_t size,
                                    const char *f, int line) {
    void *ret = calloc(nmemb, size);
    if (!ret) {
        CRITLOG("calloc returned NULL at %s:%d\n", f, line);
        abort();
    }
    return ret;
}

static inline void *_cumulus_realloc(void *ptr, size_t size,
                                    const char *f, int line) {
    void *ret = realloc(ptr, size);
    if (!ret) {
        CRITLOG("realloc returned NULL at %s:%d\n", f, line);
        abort();
    }
    return ret;
}

static inline char *_cumulus_strdup(const char *s,
                                    const char *f, int line) {
    char *ret = strdup(s);
    if (!ret) {
        CRITLOG("strdup returned NULL at %s:%d\n", f, line);
        abort();
    }
    return ret;
}

#endif
