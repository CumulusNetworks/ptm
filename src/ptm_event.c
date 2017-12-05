/*********************************************************************
 * Copyright 2013,2015 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * ptm_event.[ch] provide the glue between the lower-level protocols
 * that provide physical topology information (such as LLDP) and the
 * upstream PTM verification functionality.
 */

#define _GNU_SOURCE

#include <signal.h>
#include <sys/file.h>
#include "ptm_event.h"
#include "lldpctl.h"
#include "log.h"
#include "ptm_quagga.h"
#include "ptm_bfd.h"
#include "ptm_conf.h"
#include "ptm_nbr.h"
#include "ptm_lldp.h"
#include "ptm_ctl.h"
#include "ptm_timer.h"
#include "ptm_netlink.h"
#include "ptm_lib.h"

static FILE *pid_fp;
int g_log_level;

/* fast retry interval expressed in NS */
#define FAST_INIT_RETRY_INTERVAL (500 * NSEC_PER_MSEC)
/* slow retry interval */
#define SLOW_INIT_RETRY_INTERVAL 15
/* reconfig interval */
#define RECONFIG_RETRY_INTERVAL (NSEC_PER_MSEC)

static void ptm_init_mod_fds();
static void ptm_queue_init_retry_timer();

static void
ptmd_usage (char *argv0)
{
    fprintf(stderr, "usage: %s [OPTIONS ...]\n\n", argv0);
    fprintf(stderr, "-c    Configuration file\n");
    fprintf(stderr, "-d    Run as daemon, forever\n");
    fprintf(stderr, "-h    Print this usage.\n");
    fprintf(stderr, "-l    log level (CRIT, ERR, WARN, INFO, DEBUG).\n");
    fprintf(stderr, "See manual page for more information.\n");
    exit(10);
}

/**
 * String'ify a PTM event. Note: uses static buffer - not reentrant.
 */
char *
ptm_event_str (ptm_event_t *event)
{
    static char estr[4*BUFSIZ];
    int len = 4*BUFSIZ;
    int tlen = 0;
    char *str = estr;

    tlen += snprintf((str+tlen), (len - tlen), "%s:",
                     ptm_event_type_str(event->type));
    tlen += snprintf((str+tlen), (len - tlen), "%s:", " Local");
    if (event->lname) {
        tlen += snprintf((str+tlen), (len - tlen), " name: %s",
                     event->lname);
    }
    if (event->liface) {
        tlen += snprintf((str+tlen), (len - tlen), " iface: %s",
                     event->liface);
    }
    if (event->lmac) {
        tlen += snprintf((str+tlen), (len - tlen), " mac: %s",
                     event->lmac);
    }
    if (event->lmgmtip) {
        tlen += snprintf((str+tlen), (len - tlen), " mgmt IP: %s",
                     event->lmgmtip);
    }
    tlen += snprintf((str+tlen), (len - tlen), "%s:", ", Remote");
    if (event->rname) {
        tlen += snprintf((str+tlen), (len - tlen), " name: %s",
                     event->rname);
    }
    if (event->riface) {
        tlen += snprintf((str+tlen), (len - tlen), " iface: %s",
                     event->riface);
    }
    if (event->rdescr) {
        tlen += snprintf((str+tlen), (len - tlen), " descr: %s",
                     event->rdescr);
    }
    if (event->rmac) {
        tlen += snprintf((str+tlen), (len - tlen), " mac: %s",
                     event->rmac);
    }
    if (event->rmgmtip) {
        tlen += snprintf((str+tlen), (len - tlen), " mgmt IP: %s",
                     event->rmgmtip);
    }
    if (event->rv6addr) {
        tlen += snprintf((str+tlen), (len - tlen), " v6: %s",
                     event->rv6addr);
    }
    if (event->rv4addr) {
        tlen += snprintf((str+tlen), (len - tlen), " v4: %s",
                     event->rv4addr);
    }
    if (event->client) {
        tlen += snprintf((str+tlen), (len - tlen), "client data len %d",
                         event->client->inbuf_len);
    }

    if (event->vrf_name) {
        tlen += snprintf((str+tlen), (len - tlen), " vrf: %s",
                     event->vrf_name);
    }
    tlen += snprintf((str+tlen), (len - tlen), "\n");
    return (estr);
}

#define ALLOC_CP(field)                                         \
    if (event->field) {                                         \
        ev_new->field = strdup(event->field);                   \
        if (!ev_new->field) {                                   \
            WARNLOG("Failed to allocate for %s\n", #field);     \
        }                                                       \
    }

#define FREE(field)                      \
    if (event->field) {                  \
        free(event->field);              \
    }

/**
 * Clone the fields of an event structure.
 */
ptm_event_t *
ptm_event_clone(ptm_event_t *event)
{
    ptm_event_t *ev_new = calloc(1, sizeof(ptm_event_t));

    if (!event || !ev_new) {
        return NULL;
    }

    ev_new->type = event->type;
    ev_new->module = event->module;
    ALLOC_CP(lname);
    ALLOC_CP(rname);
    ALLOC_CP(liface);
    ALLOC_CP(riface);
    ALLOC_CP(rdescr);
    ALLOC_CP(lmac);
    ALLOC_CP(rmac);
    ALLOC_CP(lmgmtip);
    ALLOC_CP(rmgmtip);
    ALLOC_CP(rv6addr);
    ALLOC_CP(rv4addr);
    ALLOC_CP(lv6addr);
    ALLOC_CP(lv4addr);
    ALLOC_CP(vrf_name);
    ev_new->vnid = event->vnid;
    ev_new->vnid_present = event->vnid_present;
    ev_new->bfdtype = event->bfdtype;

    return (ev_new);
}

/**
 * Cleanup the fields of an event structure.
 */
void
ptm_event_cleanup (ptm_event_t *event)
{
    if (!event) {
        return;
    }

    FREE(lname);
    FREE(rname);
    FREE(liface);
    FREE(riface);
    FREE(rdescr);
    FREE(lmac);
    FREE(rmac);
    FREE(lmgmtip);
    FREE(rmgmtip);
    FREE(rv6addr);
    FREE(rv4addr);
    FREE(lv6addr);
    FREE(lv4addr);
    FREE(vrf_name);
    memset(event, 0, sizeof(ptm_event_t));
}

ptm_globals_t ptm_g = { {{.init_cb = ptm_init_timer },
                         {.init_cb = ptm_init_lldp },
                         {.init_cb = ptm_init_nl },
                         {.init_cb = ptm_init_nbr },
                         {.init_cb = ptm_init_quagga },
                         {.init_cb = ptm_init_bfd },
                         {.init_cb = ptm_init_ctl },
                         {.init_cb = NULL }}};

static void
ptmd_exit (void)
{
    ptm_globals_t *g = &ptm_g;

    PTM_SET_STATE(g, PTM_SHUTDOWN);
    ptm_lib_deregister(g->ptmlib_hdl);
    if(g->retry_timer)
        cl_timer_destroy(g->retry_timer);
    ptm_g.retry_timer = NULL;
    ptm_conf_finish ();
    ptm_shutdown_lldp ();
    INFOLOG("PTMD exiting.\n");
    fclose(pid_fp);
    _exit(0);
}

void
ptm_fd_cleanup (int fd)
{
    if (fd > 0) {
        FD_CLR(fd, &ptm_g.masterset);
        if (fd == ptm_g.maxfd) {
            while (FD_ISSET(ptm_g.maxfd, &ptm_g.masterset) == 0) {
                ptm_g.maxfd -= 1;
            }
        }
        close(fd);
    }
}

void
ptm_fd_add (int fd)
{
    if (fd > 0) {
        FD_SET(fd, &ptm_g.masterset);
        if (fd > ptm_g.maxfd) {
            ptm_g.maxfd = fd;
        }
    }
}

/* routine to call a module's event callback and
 * handle any peer callbacks as well
 */
void ptm_module_handle_event_cb(ptm_event_t *event)
{
    int m;
    ptm_globals_t *ptr_g = &ptm_g;

    if (!event) return;

    /* call the module event callback */
    if (PTM_MODULE_EVENTCB(ptr_g, event->module))
        PTM_MODULE_EVENTCB(ptr_g, event->module)(event);

    /* call any peer callbacks if registered */
    for (m = 0; m < MAX_MODULE; m++) {
        if ((m != event->module) &&
            (PTM_MODULE_PEERCB(ptr_g, m, event->module)))
            PTM_MODULE_PEERCB(ptr_g, m, event->module)(event);
    }
}

/* routine to request a re-initialization of a module */
void ptm_module_request_reinit(void)
{
    ptm_globals_t *g = &ptm_g;
    if (PTM_GET_STATE(g) != PTM_RUNNING)
        return;
    ptm_queue_init_retry_timer();
}

static int
_fd_to_module (int fd)
{
    int m;
    int i;

    for (m = 0; m < MAX_MODULE; m++) {
        for (i = 0; i < MAX_FD; i++) {
            if (ptm_g.modules[m].fd[i] == fd) {
                return (m);
            }
        }
    }
    return (CTL_MODULE);
}

static void
ptm_init_mod_fds()
{
    ptm_globals_t *g = &ptm_g;
    ptm_module_e m;
    int i;

    FD_ZERO(&g->writeset);
    FD_ZERO(&g->masterset);
    g->maxfd = 0;
    for (m = 0; m < MAX_MODULE; m++) {
        for (i = 0; i < MAX_FD; i++) {
            if (g->modules[m].fd[i] != -1) {
                FD_SET(g->modules[m].fd[i], &g->masterset);
                if (g->modules[m].fd[i] > g->maxfd) {
                    g->maxfd = g->modules[m].fd[i];
                }
            }
        }
    }
}

static void
ptm_handle_reconfig ()
{
    ptm_globals_t *g = &ptm_g;
    int mod;

    if (!g->init_retry_count) {
        INFOLOG("Starting PTM RECONFIG \n");
        cl_timer_destroy(g->retry_timer);
        g->retry_timer = NULL;
        g->retry_interval = RECONFIG_RETRY_INTERVAL;
        ptm_queue_init_retry_timer();
    }
    /* mark all modules that are not in error state */
    for (mod=LLDP_MODULE; mod != MAX_MODULE; mod++) {
        if (PTM_MODULE_GET_STATE(g, mod) != MOD_STATE_ERROR) {
            PTM_MODULE_SET_STATE(g, mod, MOD_STATE_INITIALIZED);
        }
    }
    PTM_SET_STATE(g, PTM_INIT);
}

static int
ptm_do_select ()
{
    fd_set rdset;
    fd_set wrset;
    int retval;
    int m;
    int i;
    int maxfd;
    ptm_globals_t *g = &ptm_g;

    while (1) {

        /* did we request a reconfig ? */
        if (PTM_GET_STATE(g) == PTM_RECONFIG) {
            INFOLOG("SIGUSR1 recd - pending RECONFIG\n");
            ptm_handle_reconfig ();
            continue;
        }

        /* local copy allows for late init modules to update global fd list */
        memcpy(&rdset, &g->masterset, sizeof(g->masterset));
        memcpy(&wrset, &g->writeset, sizeof(g->writeset));
        maxfd = g->maxfd;

        retval = select(maxfd+1, &rdset, &wrset, NULL, NULL);

        if (retval == -1) {
            if (errno == EINTR) continue;
            else {
                ERRLOG("select() error (%s)\n", strerror(errno));
                return (-1);
            }
        }
        if (retval == 0) continue;

        for (i = 0; i <= maxfd; i++) {

            if (FD_ISSET(i, &rdset)) {
                m = _fd_to_module(i);
#ifdef DEBUG_EVENTS
                DLOG("%s: FD %d READSET FOR MODULE %s\n", __FUNCTION__, i,
                     ptm_module_string(m));
#endif // DEBUG_EVENTS
                if (PTM_MODULE_PROCESSCB(g, m))
                    PTM_MODULE_PROCESSCB(g, m)(i, SOCKEVENT_READ, NULL);
            }

            if (FD_ISSET(i, &wrset)) {
                m = _fd_to_module(i);
                DLOG("%s: FD %d WRITESET FOR MODULE %s\n", __FUNCTION__, i,
                    ptm_module_string(m));
                if (PTM_MODULE_PROCESSCB(g, m))
                    PTM_MODULE_PROCESSCB(g, m)(i, SOCKEVENT_WRITE, NULL);
            }
        }
    }
    return (0);
}

static void
ptm_sigusr1_cb (int signum)
{
    ptm_globals_t *g = &ptm_g;

    PTM_SET_STATE(g, PTM_RECONFIG);
}

static int
ptm_set_signal_handler (int signum,
                        void (*handler)(int))
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;

    if (sigaction(signum, &sa, NULL) != 0) {
        ERRLOG("sigaction failed for signal %d, %s\n", signum, strerror(errno));
        return (-1);
    }

    return (0);
}

static int ptm_get_error_mods(void)
{
    ptm_globals_t *g = &ptm_g;
    int ret = 0;
    ptm_module_e m;

    for (m = 0; m < MAX_MODULE; m++) {
        if (PTM_MODULE_GET_STATE(g, m) == MOD_STATE_ERROR)
            ret |= (1 << m);
    }

    return ret;
}

static void
ptm_init_retry_timer (cl_timer_t *timer,
                      void *context)
{
    ptm_globals_t *g = &ptm_g;
    int ret;
    ptm_module_e m;

    for (m = 0; m < MAX_MODULE; m++) {
        if (PTM_MODULE_GET_STATE(g, m) == MOD_STATE_ERROR) {
            PTM_MODULE_INITCB(g, m)(g);
        }
    }

    if (!ptm_get_error_mods()) {
        DLOG("%s: All Modules Re-initialized \n", __FUNCTION__);
    }

    /* attempt to read topo file */
    ret = ptm_conf_init(g);

    if (ret) {
        if (!g->my_hostname || !g->my_mgmtip) {
            /* did not get hostname/ip from lldpd - keep retrying */
            if (g->init_retry_count == LONG_MAX)
                g->init_retry_count = MAX_FAST_INIT_RETRY_COUNT;
            g->init_retry_count++;
            if (g->init_retry_count == MAX_FAST_INIT_RETRY_COUNT) {
                INFOLOG("PTM max fast retries done [%d] - "
                        "switching to slow retry\n",
                        MAX_FAST_INIT_RETRY_COUNT);
                cl_timer_destroy(g->retry_timer);
                g->retry_timer = NULL;
                g->retry_interval = SLOW_INIT_RETRY_INTERVAL;
                ptm_queue_init_retry_timer();
            }
        } else {
            /* hostname/ip valid - but topo read failure */
            INFOLOG("PTM topology file errors - "
                    "Issue restart/reconfig\n");
            g->conf_init_done = TRUE;
        }
    }

    /* give a chance for each module to populate
     * with current state/data
     */
    for (m = 0; m < MAX_MODULE; m++) {
        if (PTM_MODULE_GET_STATE(g, m) != MOD_STATE_ERROR) {
            if (PTM_MODULE_POPULATECB(g, m))
                PTM_MODULE_POPULATECB(g, m)(g);
            if (PTM_MODULE_GET_STATE(g, m) != MOD_STATE_ERROR)
                PTM_MODULE_SET_STATE(g, m, MOD_STATE_RUNNING);
        }
    }

    if (!ptm_get_error_mods() && g->conf_init_done) {
        INFOLOG("%s: Init sequence complete \n", __FUNCTION__);
        g->init_retry_count = 0;
        g->retry_interval = FAST_INIT_RETRY_INTERVAL;
        cl_timer_destroy(g->retry_timer);
        g->retry_timer = NULL;
        PTM_SET_STATE(g, PTM_RUNNING);
    }

    return;
}

static void
ptm_queue_init_retry_timer()
{
    int flags;
    if (!ptm_g.retry_timer) {
        ptm_g.retry_timer = cl_timer_create();
        flags = T_UF_PERIODIC;
        if (ptm_g.retry_interval != SLOW_INIT_RETRY_INTERVAL)
            flags |= T_UF_NSEC;
        cl_timer_arm(ptm_g.retry_timer, ptm_init_retry_timer,
                     ptm_g.retry_interval, flags);
    }
}

int
main (int argc, char *argv[])
{
    ptm_globals_t *g = &ptm_g;
    int ret;
    int ch;
    char file[MAXNAMELEN];
    int m, my_pid;
    bool daemonize = FALSE;
    char loglevel[16] = "INFO";
    unsigned int retry_mods;

    sprintf(file, "%s/%s", PTM_CONF_DIR, PTM_CONF_FILE);
    while ((ch = getopt(argc, argv, "dhc:l:")) != -1) {
        switch(ch) {
        case 'c':
            strncpy(file, optarg, MAXNAMELEN-1);
            break;
        case 'd':
            daemonize = TRUE;
            break;
        case 'l':
            strncpy(loglevel, optarg, sizeof(loglevel));
            break;
        case 'h':
        default:
            ptmd_usage(argv[0]);
            exit(0);
        }
    }

    /*
     * Check to see if another ptmd is running.
     */
    if ((pid_fp = fopen(PTM_PIDFILE, "a+")) == NULL) {
        fprintf(stderr, "Couldn't open pid file %s\n", PTM_PIDFILE);
        exit (1);
    } else {
        /* Use file locking to ensure we're the only instance */
        /* XXX: Use lockf() if ported to other platforms */
        /* Using flock as it works across daemon() call */
        if (flock(fileno(pid_fp), LOCK_EX | LOCK_NB) < 0) {
            fscanf(pid_fp, "%d", &my_pid);
            fprintf(stderr, "Another instance of ptmd ? (PID=%d, err=%s)\n",
                    my_pid, strerror(errno));
            exit(1);
        }
    }

    if (!strncmp(loglevel, "WARN", sizeof(loglevel-1))) {
        g_log_level = LOG_WARNING;
    } else if (!strncmp(loglevel, "CRIT", sizeof(loglevel-1))) {
        g_log_level = LOG_CRIT;
    } else if (!strncmp(loglevel, "DEBUG", sizeof(loglevel-1))) {
        g_log_level = LOG_DEBUG;
    } else {
        g_log_level = LOG_INFO;
    }

    openlog(program_invocation_short_name, LOG_NDELAY | LOG_PID | LOG_CONS,
            LOG_DAEMON);

    /* Disable SIGHUP, until handlers are installed
     * This was used to rotate logs.  Leave it ignored, since
     * we don't want SIGHUP to terminate us if people had
     * scripts sending HUP directly.
     */
    signal(SIGHUP, SIG_IGN);

    INFOLOG("Starting PTM INIT\n");

    if (daemonize)
        daemon(0, 0);

    /* The PID will now be right */
    ftruncate(fileno(pid_fp), 0);
    fprintf(pid_fp, "%d\n", getpid());
    fflush(pid_fp);

    ptm_g.retry_interval = FAST_INIT_RETRY_INTERVAL;
    PTM_SET_STATE(g, PTM_INIT);
    /* initialize the modules */
    retry_mods = 0;
    for (m = 0; m < MAX_MODULE; m++) {
        if (PTM_MODULE_INITCB(g, m)) {
            ret = PTM_MODULE_INITCB(g, m)(g);
            if (ret) {
                /* init failed - retry init */
                fprintf(stderr, "Module %s init failed \n",
                        ptm_module_string(m));
                retry_mods |= (1 << m);
            }
        } else {
            PTM_MODULE_INITIALIZE(g, m);
        }
    }

    if (retry_mods) {
        /* create a timer event to retry failed modules */
        ptm_queue_init_retry_timer();
    }

    atexit(ptmd_exit);

    strcpy(g->topo_file, file);
    INFOLOG("Local host name %s, IP %s\n", g->my_hostname, g->my_mgmtip);

    /* attempt to read topo file */
    ret = ptm_conf_init(g);

    if (ret) {
        ptm_queue_init_retry_timer();
    }

    /* give a chance for each module to populate
     * with current state/data
     */
    for (m = 0; m < MAX_MODULE; m++) {
        /* if a module is pending retry ignore it */
        if (!!(retry_mods & (1 << m)))
            continue;
        if (PTM_MODULE_POPULATECB(g, m))
            PTM_MODULE_POPULATECB(g, m)(g);
        PTM_MODULE_SET_STATE(g, m, MOD_STATE_RUNNING);
    }

    PTM_SET_STATE(g, PTM_RUNNING);

    ptm_init_mod_fds();

    ptm_set_signal_handler(SIGUSR1, ptm_sigusr1_cb);
    ptm_do_select();

    return (ret);
}
