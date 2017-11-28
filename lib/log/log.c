/* Copyright 2010,2015 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */
#include "cumulus.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <errno.h>
#undef _GNU_SOURCE
#include <syslog.h>
#include <time.h>
#include <execinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include "itimer.h"

#include "log.h"

const char *log_level_strings[] = {
    "CRIT", "ERR", "WARN", "INFO", "DEBUG"
};
int log_level_syslog_levels[] = {
    LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG
};

enum log_level_e _min_log_level = LOG_LEVEL_LAST;

struct log_backend_s;
typedef struct log_backend_s {
    enum log_level_e level;

    void (*log)(struct log_backend_s *backend, enum log_level_e level,
                const char *fmt, int fmt_len, va_list varg);
    bool (*reopen)(struct log_backend_s *backend);
    void (*close)(struct log_backend_s *backend);

    char *params;
    void *userdata;
} log_backend_t;

log_backend_t *log_backends = NULL;
int num_backends = 0;

void log_backtrace(void)
{
    void *buf[256];
    int num, i;
    int tid = syscall(SYS_gettid);

    num = backtrace(buf, ARRAY_SIZE(buf));
    for (i = 0; i < num; i++) {
        LOG("STACK %d: %p\n", tid, buf[i]);
    }
}

/*
 * Override assert.h's __assert_fail() to log here instead of stderr.
 */
void __assert_fail(const char *assertion, const char *file,
                   unsigned int line, const char *function)
{
    CRITLOG("%s:%u: %s%sAssertion `%s' failed.\n",
            file, line,
            function ? function : "", function ? ": " : "",
            assertion);
    log_backtrace();

    abort();
}

enum log_level_e log_string_to_level(const char *str)
{
    int i;

    for (i = 0; i < LOG_LEVEL_LAST; i++) {
        if (strcmp(log_level_strings[i], str) == 0) {
            return i;
        }
    }

    return INT_MAX;
}

const char *log_level_to_string(enum log_level_e level)
{
    if (level >= LOG_LEVEL_LAST) {
        assert(FALSE);
        return "INVALID";
    } else {
        return log_level_strings[level];
    }
}

const char *_log_datestamp(void)
{
    struct timeval tv;
    struct tm* tm;
    static char buf[128]; /* XXX This is racy w/ multiple threads logging! */
    size_t c;

    if (gettimeofday(&tv, NULL) < 0) {
        return "-1";
    }

    tm = localtime(&(tv.tv_sec));

    c = snprintf(buf, sizeof(buf) - 1, "%lu.%06lu", tv.tv_sec, tv.tv_usec);
    strftime(&buf[c], (sizeof(buf)-c-1), " %F %T", tm);
    buf[sizeof(buf) - 1] = '\0';

    return buf;
}

static void log_file(struct log_backend_s *backend,
                     enum log_level_e level, const char *fmt, int fmt_len,
                     va_list varg)
{
    FILE *fp = (FILE *)backend->userdata;

    if (fp) {
        vfprintf(fp, fmt, varg);
        fflush(fp);
    }
}

static bool log_file_reopen(struct log_backend_s *backend)
{
    FILE *fp = (FILE *)backend->userdata;

    assert(backend->params);
    if (backend->params) { /*  check in case asserts not enabled */
        if (fp) /*  use freopen to reduce race condition window */
            backend->userdata = freopen(backend->params, "a", fp);
        else 
            backend->userdata = fopen(backend->params, "a");
    }

    if (!backend->params || !backend->userdata) {
        fprintf(stderr, "Couldn't open logfile '%s'\n",
            backend->params ?  backend->params : "NOTSET");
        return FALSE;
    }

    return TRUE;
}

static void log_file_close(struct log_backend_s *backend)
{
    FILE *fp = (FILE *)backend->userdata;

    if (fp) {
        backend->userdata = NULL;
        fclose(fp);
    }
}

/*  this is never actually called, we use it just as the indicator for syslog */
static void log_syslog(struct log_backend_s *backend,
                       enum log_level_e level, const char *fmt, int fmt_len,
                       va_list varg)
{
    int syslog_level;

    syslog(LOG_WARNING, "Function %s should never be called directly",
        __func__);

    if (level < 0) {
        syslog_level = LOG_NOTICE;
    } else {
        syslog_level = log_level_syslog_levels[level];
    }
    vsyslog(syslog_level, fmt, varg);
}

static void log_syslog_close(struct log_backend_s *backend)
{
    closelog();
}

static void log_program(struct log_backend_s *backend,
                        enum log_level_e level, const char *fmt, int fmt_len,
                        va_list varg)
{
    static int failed_count = 0;
    pid_t pid;
    int status;
    char buf[4096];

    if (failed_count > 10) {
        return;
    }

    switch ((pid = fork())) {
    default: /* parent */
        if (waitpid(pid, &status, 0) < 0 || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Logging program '%s' returned failure\n",
                    backend->params);
            failed_count = 1000;
        } else {
            failed_count = 0; /* success, reset the count. */
        }
        break;
    case 0: /* child */
        if (vsnprintf(buf, sizeof (buf) - 1, fmt, varg) < 0) {
            fprintf(stderr, "vsnprintf of log message failed\n");
            exit(99);
        }
        buf[sizeof (buf) - 1] = '\0';
        if (execl((const char *)backend->params,
                  (const char *)backend->params, buf, NULL) < 0) {
            perror("Failed to exec logging program");
            exit(100);
        }
        exit(101);
        break;
    case -1: /* error */
        perror("Failed to fork logging program");
        failed_count++;
        break;
    }
}

/*
 * Strip off the timestamp/file/line header for continuation lines and syslog.
 * See the _log_log call in log.h
 */
#define _STRIP_ARGS(stripcnt, format, format_len, args)  \
    if (1) {  \
        int space_count = 0;  \
        while (*(format)) {  \
            if (space_count == (stripcnt)) {  \
                /* Skip the args matching the params we skipped in format. */  \
                va_arg((args), void *);  \
                if ((stripcnt) > 1) { /*  skip file and lineo */  \
                    va_arg((args), void *);  \
                    va_arg((args), void *);  \
                } \
                break;  \
            }  \
            if (*(format) == ' ')  { \
                space_count++;  \
            }  \
            (format)++;  \
            (format_len)--;  \
        }  \
    } \
    else /* eat the ";" after macro */

/*
 * lots of special handling, so separate function.
 * We need to buffer multiple log calls without newlines,
 * and we need to split up messages with embedded newlines
 * into separate syslog calls to avoid the #012 conversion
 * (which is needed for correct remote syslog)
 * The net of this is that we always have to snprintf, and
 * then check the buffer for newlines (embedded and trailing).
 */
static void _handle_syslog(enum log_level_e level, const char *sfmt, 
                           va_list sargs)
{
    static int buflen;
    static char *buffered;
    int syslog_level, llen, tlen;
    char _lbuf[4096]; /* rsyslog currently truncates at about 2KB */
    char *lbuf = _lbuf;
    char *nlp, *logbuf;
    bool freebuf = FALSE;

    if (level < 0) {
        syslog_level = LOG_NOTICE;
    } else {
        syslog_level = log_level_syslog_levels[level];
    }

    /*
     * don't want the log library timestamps for syslog, so strip first fmt
     * spec and first arg; we don't use the arg len, so pass a dummy
     */
    tlen = 2;
    _STRIP_ARGS(1, sfmt, tlen, sargs);

    if (buflen) { /*  don't put file:lineno in continuation lines */
        _STRIP_ARGS(1, sfmt, tlen, sargs);
        /*  skipping 1 word, but two fmt specs, so 2 args, not 1 */
        va_arg(sargs, void *);
        if (level >= LOG_LEVEL_CRIT && level <= LOG_LEVEL_WARN) {
            /*  don't put the WARN, etc. into continuation lines, either */
            char *sp = strchr(sfmt, ' ');
            if (sp) {
                sfmt = sp + 1;
            }
        }
    }

    tlen = vsnprintf(_lbuf, sizeof _lbuf, sfmt, sargs);
    llen = strlen(lbuf); /*  should be sizeof lbuf - 1, but be sure */
    if (tlen >= sizeof _lbuf) {
        syslog(LOG_WARNING, "Log message longer than %u "
            "characters, truncated (began with %.60s)",
            (unsigned)sizeof _lbuf, lbuf);
    }

    /*
     * append if already buffered, or start buffering if doesn't have at least
     * one newline (may have embedded newlines); if so we buffer at end via 
     * strdup, if it didn't end in newline
     */
    if (buflen || !strchr(lbuf, '\n')) {
        char *rbuf;
        int nlen;

        rbuf = realloc(buffered, buflen + llen + 1);
        if (!rbuf) {
            syslog(LOG_WARNING, "Log message could not be "
                "buffered, flushing");
            if (buflen) {
                syslog(syslog_level, "%s", buffered);
            }
            syslog(syslog_level, "%s", lbuf);
            lbuf = NULL;
            goto cleanup;
        }
        nlen = snprintf(rbuf+buflen, llen + 1, "%s", lbuf);
        lbuf = NULL;
        buflen = nlen + buflen;
        buffered = rbuf;
        logbuf = buffered;
    } else { 
        /*  we are going to do the "normal" thing and log the whole buffer */
        logbuf = lbuf;
    }

    /*  may not be anything this time */
    for(nlp=strchr(logbuf, '\n'); nlp; nlp=strchr(logbuf, '\n')) {
        *nlp = '\0';
        syslog(syslog_level, "%s", logbuf);
        logbuf = nlp + 1; /*  advance to next part of string */
    }
    if (!*logbuf && buflen) {
        freebuf = TRUE; /*  we're done, all flushed */
    } else if (logbuf != buffered) {
        /*  we flushed some, but not all, logbuf could be malloced or _lbuf */
        if (*logbuf)
            lbuf = strdup(logbuf);
        else
            lbuf = NULL;
        freebuf = TRUE;
    }
cleanup:
    if (freebuf && buflen) {
        free(buffered);
        buffered = NULL;
        buflen = 0;
    }
    if (lbuf && *lbuf) { /* buffer remaining until newline is logged */
        buffered = lbuf;
        buflen = strlen(buffered);
    }
}

void _log_log(enum log_level_e level, const char *fmt, int fmt_len, ...)
{
    static __thread bool last_had_newline = TRUE;
    int i;
    va_list varg;
    int spaces_to_strip = 2;
    bool stripfmt = FALSE;

    va_start(varg, fmt_len);

    if (!last_had_newline || !log_backends || num_backends <= 0) {
        /*
         * Sometimes we print a single line using multiple *LOG calls, with only
         * the last having a newline.  We only want to print a timestamp and
         * file/line header once per line, so we keep track and only print the
         * header if the last line ended in a '\n'.  We strip just before the
         * actual logging call below, because syslog doesn't want them stripped.
         * If this is WARN/ERR/CRIT, strip off the loglevel too.
         */
        stripfmt = TRUE;
        if (level >= LOG_LEVEL_CRIT && level <= LOG_LEVEL_WARN) {
            spaces_to_strip++;
        }
    }
    last_had_newline = fmt[fmt_len - 2] == '\n';

    if (!log_backends || num_backends <= 0) {
        vfprintf(stderr, fmt, varg);
        fflush(stderr);
    } else {
        for (i = 0; i < num_backends; i++) {
            log_backend_t log_backend_i;
            if (!log_backends) {
                continue;
            }
            log_backend_i = log_backends[i];
            if (log_backend_i.level >= level) {
                va_list tmp;
                va_copy(tmp, varg);
                if (log_backend_i.log == log_syslog) {
                    /*  lots of special handling, so separate function */
                    _handle_syslog(level, fmt, tmp);
                } else {
                    const char *mfmt = fmt;
                    int mlen = fmt_len;
                    if (stripfmt) {
                        _STRIP_ARGS(spaces_to_strip, mfmt, mlen, tmp);
                    }
                    log_backend_i.log(&log_backend_i, level, mfmt, mlen, tmp);
                }
                va_end(tmp);
            }
        }
    }

    va_end(varg);
}


bool log_reopen(void)
{
    bool ret = TRUE;
    int i;

    for (i = 0; i < num_backends; i++) {
        if (log_backends[i].reopen) {
            ret = log_backends[i].reopen(&log_backends[i]) ? ret : FALSE;
        }
    }
    return ret;
}

static bool log_backend_init(const char *str, log_backend_t *backend)
{
    const char *params = strchr(str, ':');
    int str_len = strlen(str);

    if (params) {
        backend->params = strdup(params + 1);
        str_len = params - str;
    }

    if (strncmp(str, "stderr", str_len) == 0) {
        assert(params == NULL);
        backend->log = log_file;
        backend->userdata = stderr;
    } else if (strncmp(str, "file", str_len) == 0) {
        char *old_params = backend->params;

        log_file_reopen(backend);

        backend->log = log_file;
        backend->reopen = log_file_reopen;
        backend->close = log_file_close;
        /* Canonicalize the path, since daemon-mode cd's to / */
        backend->params = realpath(backend->params, NULL);
        free(old_params);
    } else if (strncmp(str, "syslog", str_len) == 0) {
        openlog(program_invocation_short_name, LOG_NDELAY | LOG_PID | LOG_CONS,
            LOG_DAEMON);
        backend->log = log_syslog;
        backend->close = log_syslog_close;
    } else if (strncmp(str, "program", str_len) == 0) {
        if (!params || access(backend->params, X_OK) < 0) {
            fprintf(stderr, "Program '%s' doesn't exist or is not executable\n",
                    backend->params);
            return FALSE;
        }
        backend->log = log_program;
    } else {
        fprintf(stderr, "Unknown log backend '%s'\n", str);
        return FALSE;
    }

    return TRUE;
}

static bool log_valid_setting(const char *str, enum log_level_e *level)
{
    char *level_str = strchr(str, '=');

    *level = LOG_LEVEL_LAST;

    if (!level_str) {
        fprintf(stderr,
                "Log backend '%s' must have a level and backend.\n", str);
        return FALSE;
    }
    level_str++;

    *level = log_string_to_level(level_str);
    if (*level >= LOG_LEVEL_LAST) {
        fprintf(stderr, "Log backend '%s' has invalid level '%s'.\n",
                str, level_str);
        return FALSE;
    }

    level_str[-1] = '\0'; /* so str doesn't include the =LEVEL part. */

    return TRUE;
}

static bool log_valid_settings(const char **strs, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        char *str = strdup(strs[i]);
        enum log_level_e level;

        if (!log_valid_setting(str, &level)) {
            free(str);
            return FALSE;
        }

        free(str);
    }

    return TRUE;
}

/* 
 *  I strongly recommend that if you add use of this logging code, that you
 *  default to file: logging, but instead default to syslog.   If you aren't
 *  adding a configuration capability for logging style, please use just syslog
 *  (see ptm/ptm_event.c for an example).  If you want to have it configurable,
 *  see switchd/switchd.c and it's fuse filesystem for both initial and on the
 *  fly changes.
 */  
bool log_init(const char **strs, int num)
{
    int i;
    log_backend_t *lbackends;
    char *str;

    lbackends = CALLOC(num, sizeof (*log_backends));

    for (i = 0; i < num; i++) {
        enum log_level_e level;

        str = strdup(strs[i]);
        if (!str)
            goto failinit;
        if (!log_valid_setting(str, &level)) {
            goto failinit;
        }

        if (!log_backend_init(str, &lbackends[i])) {
            goto failinit;
        }
        lbackends[i].level = level;

        if (level < _min_log_level) {
            _min_log_level = level;
        }

        free(str);
    }
    log_backends = lbackends;
    num_backends = num;

    itimer_init();

    return TRUE;
failinit:
    for (; i>=0; i--)
        if (lbackends[i].close)
            lbackends[i].close(&lbackends[i]);
    free(lbackends);
    if (str)
        free(str);
    return FALSE;
}

void log_deinit(void)
{
    int i, num_ends = num_backends;
    log_backend_t *lbackends = log_backends;

    /*  clear early, minimize race conditions */
    log_backends = NULL;
    num_backends = 0;

    if (!lbackends)
        return;

    for (i = 0; i < num_ends; i++)
        if (lbackends[i].close)
            lbackends[i].close(&lbackends[i]);

    free(lbackends);
    _min_log_level = LOG_LEVEL_LAST;
}

bool log_setup(const char **strs, int num)
{
    if (!log_valid_settings(strs, num))
        return FALSE;
    log_deinit();
    return log_init(strs, num);
}
