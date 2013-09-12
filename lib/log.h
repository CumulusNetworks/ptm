/* Copyright 2013 Cumulus Networks Inc.  All rights reserved. */
/* See License file for licenese. */

#ifndef _LOG_H_
#define _LOG_H_

enum log_level_e {
    LOG_LEVEL_ALWAYS = -1,
    LOG_LEVEL_CRIT = 0,
    LOG_LEVEL_ERR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_LAST
};

bool log_init(const char **backends, int num_backends);
enum log_level_e log_string_to_level(const char *str);
const char *log_level_to_string(enum log_level_e level);
bool log_reopen(void);
void log_backtrace(void);

#ifdef NDEBUG
#    define DLOG(...)
#else
#    define DLOG(fmt, ...) _DO_LOG(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#endif
#define INFOLOG(fmt, ...) _DO_LOG(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define WARNLOG(fmt, ...) _DO_LOG(LOG_LEVEL_WARN, "WARN " fmt, ##__VA_ARGS__)
#define ERRLOG(fmt, ...) _DO_LOG(LOG_LEVEL_ERR, "ERR " fmt, ##__VA_ARGS__)
#define CRITLOG(fmt, ...) _DO_LOG(LOG_LEVEL_CRIT, "CRIT " fmt, ##__VA_ARGS__)
#define LOG(fmt, ...) _DO_LOG(LOG_LEVEL_ALWAYS, fmt, ##__VA_ARGS__)

#define MALLOC(sz) _cumulus_malloc(sz, __FILE__, __LINE__)
#define CALLOC(nmemb, sz) _cumulus_calloc(nmemb, sz, __FILE__, __LINE__)
#define REALLOC(ptr, sz) _cumulus_realloc(ptr, sz, __FILE__, __LINE__)

/******************************************************************/

#define IF_LOG(lvl) if (_min_log_level >= (LOG_LEVEL_##lvl))

extern enum log_level_e _min_log_level;
#define _DO_LOG(lvl, fmt, ...)                                          \
    if (_min_log_level >= (lvl))                                        \
        _log_log((lvl), "%s %s:%d " fmt, sizeof ("%s %s:%d " fmt),      \
                 _log_datestamp(), __FILE__, __LINE__,                  \
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

#endif
