/* Copyright 2013 Cumulus Networks Inc.  All rights reserved. */
/* See License file for licenese. */

#include "cumulus.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
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

    char *params;
    void *userdata;
} log_backend_t;

log_backend_t *backends = NULL;
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

void _log_log(enum log_level_e level, const char *fmt, int fmt_len, ...)
{
    static bool last_had_newline = TRUE;
    int i;
    va_list varg;

    va_start(varg, fmt_len);

    /*
     * Sometimes we print a single line using multiple *LOG calls, with
     * only the last having a newline.  We only want to print a timestamp and
     * file/line header once per line, so we keep track and only print the
     * header if the last line ended in a '\n'.
     */
    if (!last_had_newline || !backends || num_backends <= 0) {
        int space_count = 0;
        int spaces_to_strip = 2;

        /* If this is WARN/ERR/CRIT, strip off the loglevel too. */
        if (level >= LOG_LEVEL_CRIT && level <= LOG_LEVEL_WARN) {
            spaces_to_strip++;
        }

        /* Strip off the timestamp/file/line header. */
        while (*fmt) {
            if (space_count == spaces_to_strip) {
                /* Skip the args corresponding to params we skipped in fmt. */
                va_arg(varg, void *);
                va_arg(varg, void *);
                va_arg(varg, void *);
                break;
            }
            if (*fmt == ' ') {
                space_count++;
            }
            fmt++;
            fmt_len--;
        }
    }
    last_had_newline = fmt[fmt_len - 2] == '\n';

    if (!backends || num_backends <= 0) {
        vfprintf(stderr, fmt, varg);
        fflush(stderr);
    } else {
        for (i = 0; i < num_backends; i++) {
            if (backends[i].level >= level) {
                va_list tmp;
                va_copy(tmp, varg);
                backends[i].log(&backends[i], level, fmt, fmt_len, tmp);
                va_end(tmp);
            }
        }
    }

    va_end(varg);
}

static void log_file(struct log_backend_s *backend,
                     enum log_level_e level, const char *fmt, int fmt_len,
                     va_list varg)
{
    FILE *fp = (FILE *)backend->userdata;

    vfprintf(fp, fmt, varg);
    fflush(fp);
}

static bool log_file_reopen(struct log_backend_s *backend)
{
    FILE *fp = (FILE *)backend->userdata;

    assert(backend->params);

    if (fp) {
        fclose(fp);
    }
    if (!backend->params ||
        (backend->userdata = fopen(backend->params, "a")) == NULL) {
        fprintf(stderr, "Couldn't open logfile '%s'\n", backend->params);
        return FALSE;
    }

    return TRUE;
}

static void log_syslog(struct log_backend_s *backend,
                       enum log_level_e level, const char *fmt, int fmt_len,
                       va_list varg)
{
    int syslog_level;

    if (level < 0) {
        syslog_level = LOG_NOTICE;
    } else {
        syslog_level = log_level_syslog_levels[level];
    }
    vsyslog(syslog_level, fmt, varg);
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

bool log_reopen(void)
{
    bool ret = TRUE;
    int i;

    for (i = 0; i < num_backends; i++) {
        if (backends[i].reopen) {
            ret = backends[i].reopen(&backends[i]) ? ret : FALSE;
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
        /* Canonicalize the path, since daemon-mode cd's to / */
        backend->params = realpath(backend->params, NULL);
        free(old_params);
    } else if (strncmp(str, "syslog", str_len) == 0) {
        openlog("switchd", LOG_NDELAY | LOG_PID | LOG_CONS, LOG_DAEMON);
        backend->log = log_syslog;
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

bool logger_init(const char **strs, int num)
{
    int i;

    backends = CALLOC(num, sizeof (*backends));
    num_backends = num;

    for (i = 0; i < num; i++) {
        char *str = strdup(strs[i]);
        char *level_str = strchr(str, '=');
        enum log_level_e level;

        if (!level_str) {
            fprintf(stderr,
                    "Log backend '%s' must have a level and backend.\n", str);
            free(str);
            return FALSE;
        }
        level_str++;

        level = log_string_to_level(level_str);
        if (level >= LOG_LEVEL_LAST) {
            fprintf(stderr, "Log backend '%s' has invalid level '%s'.\n",
                    str, level_str);
            free(str);
            return FALSE;
        }

        level_str[-1] = '\0'; /* so str doesn't include the =LEVEL part. */

        if (!log_backend_init(str, &backends[i])) {
            free(str);
            return FALSE;
        }
        backends[i].level = level;

        if (level < _min_log_level) {
            _min_log_level = level;
        }

        free(str);
    }

    itimer_init();

    return TRUE;
}
