/*********************************************************************
 * Copyright 2013 Cumulus Networks, Inc.  All rights reserved.
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
#include "ptm_msg.h"

static FILE *pid_fp;

/* retry interval expressed in NS */
#define INIT_RETRY_INTERVAL (100 * NSEC_PER_MSEC)

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
    memset(event, 0, sizeof(ptm_event_t));
}

#ifdef TEST
void
ptm_event_default_handler (ptm_event_t *event)
{
    ptm_client_t *client;
    ptm_client_t *save;
    //char *str = "world";
    char str1[100];
    //int rc;
    csv_t *csv = NULL;
    csv_record_t *rec;
    int len;

    LOG("%s", ptm_event_str(event));
    switch(event->module) {
    case CTL_MODULE:
        /* U-turn the request to the client - just a test */
        //ptm_ctl_send(event->client, event->client->inbuf,
        //             event->client->inbuf_len);

        memset(str1, -1, sizeof(str1));
        client = ptm_client_safe_iter(&save);
        while (client != NULL) {
            LOG("client#%d\n", client->fd);
            csv = csv_init(csv, str1, 100);
            LOG("client#%d\n", client->fd);
            rec = ptm_msg_encode_header(csv, NULL, 0, PTM_VERSION);
            ptm_msg_encode_port_header(csv);
            csv_encode(csv, 2, "swp1", "pass");
            csv_encode(csv, 2, "swp2", "pass");
            csv_encode(csv, 2, "swp3", "pass");
            len = csvlen(csv);
            len -= PTM_MSG_HEADER_LENGTH;
            ptm_msg_encode_header(csv, rec, len, PTM_VERSION);
            ptm_ctl_send(client, str1, csvlen(csv));
            csv_clean(csv);
            client = ptm_client_safe_iter_next(&save);
        }
        break;
    default:
        break;
    }
}
#endif

ptm_globals_t ptm_g = { {{.init_cb = ptm_init_timer },
                         {.init_cb = ptm_init_lldp },
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
    if (fd) {
        FD_CLR(fd, &ptm_g.masterset);
        if (fd == ptm_g.maxfd) {
            while (FD_ISSET(ptm_g.maxfd, &ptm_g.masterset) == 0) {
                ptm_g.maxfd -= 1;
            }
        }
    }
    close(fd);
}

void
ptm_fd_add (int fd)
{
    if (fd) {
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
    if (PTM_GET_STATE(g) == PTM_SHUTDOWN)
        return;
    ptm_queue_init_retry_timer();
}

static int
_fd_to_module (int fd)
{
    int m;

    for (m = 0; m < MAX_MODULE; m++) {
        if (ptm_g.modules[m].fd == fd) {
            return (m);
        }
    }
    return (CTL_MODULE);
}

static void
ptm_init_mod_fds()
{
    ptm_globals_t *g = &ptm_g;
    ptm_module_e m;

    FD_ZERO(&g->writeset);
    FD_ZERO(&g->masterset);
    g->maxfd = 0;
    for (m = 0; m < MAX_MODULE; m++) {
        if (g->modules[m].fd != -1) {
            FD_SET(g->modules[m].fd, &g->masterset);
            if (g->modules[m].fd > g->maxfd) {
                g->maxfd = g->modules[m].fd;
            }
            PTM_MODULE_SET_STATE(g, m, MOD_STATE_RUNNING);
        }
    }
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

    PTM_SET_STATE(g, PTM_RUNNING);
    ptm_init_mod_fds();

    while (1) {
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
    int mod;

    DLOG("%s: Signal %d received\n", __FUNCTION__, signum);

    PTM_SET_STATE(g, PTM_RECONFIG);
    ptm_queue_init_retry_timer();
    ptm_conf_finish ();
    /* mark all modules that are not in error state */
    for (mod=LLDP_MODULE; mod != MAX_MODULE; mod++) {
        if (PTM_MODULE_GET_STATE(g, mod) != MOD_STATE_ERROR) {
            PTM_MODULE_SET_STATE(g, mod, MOD_STATE_INITIALIZED);
        }
    }
}

static void
ptm_sigterm_cb (int signum)
{
    ptmd_exit();
}

static void ptm_sighup_cb(int signum)
{
    INFOLOG("SIGHUP recieved, reopening log file.\n");
    log_reopen();
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

    if (!g->my_hostname || !g->my_mgmtip) {
        /* hostname/mgmtip missing - delay again */
        DLOG("%s: Hostname (%s) and/or MgmtIP (%s) "
             "still missing post-pone config read\n",
             __FUNCTION__, g->my_hostname, g->my_mgmtip);
        return;
    }

    /* build from scratch or just re-parse? */
    if (!g->conf_init_done)
        ret = ptm_conf_init(g);
    else
        ret = ptm_conf_reparse(g);

    if (!ret) {
        /* give a chance for each module to populate
         * with current state/data
         */
        for (m = 0; m < MAX_MODULE; m++) {
            if (PTM_MODULE_GET_STATE(g, m) == MOD_STATE_PARSE) {
                if (PTM_MODULE_POPULATECB(g, m))
                    PTM_MODULE_POPULATECB(g, m)(g);
                else
                    PTM_MODULE_SET_STATE(g, m, MOD_STATE_POPULATE);
            }
        }
    }

    if (!ptm_get_error_mods() && g->conf_init_done) {
        DLOG("%s: Init sequence complete \n", __FUNCTION__);
        cl_timer_destroy(g->retry_timer);
        g->retry_timer = NULL;
        PTM_SET_STATE(g, PTM_RUNNING);
    }

    return;
}

static void
ptm_queue_init_retry_timer()
{
    if (!ptm_g.retry_timer) {
        ptm_g.retry_timer = cl_timer_create();
        cl_timer_arm(ptm_g.retry_timer, ptm_init_retry_timer,
                     INIT_RETRY_INTERVAL, (T_UF_PERIOIDIC | T_UF_NSEC));
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
    char tmplogstr[MAXNAMELEN+sizeof(loglevel)+8];
    const char *logstr[2];
    int postpone_init = FALSE;

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

    sprintf(tmplogstr, "file:%s=%s", PTM_LOGFILE, loglevel);
    logstr[0] = strdupa(tmplogstr);
    ret = logger_init(logstr, 1);
    if (!ret) {
        fprintf(stderr, "Log init failed (%s), exiting.\n", tmplogstr);
        exit(11);
    }

	/* Disable SIGHUP, until handlers are installed */
	signal(SIGHUP, SIG_IGN);

    if (daemonize)
        daemon(0, 0);

    /* The PID will now be right */
    ftruncate(fileno(pid_fp), 0);
    fprintf(pid_fp, "%d\n", getpid());
    fflush(pid_fp);

    PTM_SET_STATE(g, PTM_INIT);
    /* initialize the modules */
    ptm_g.retry_mods = 0;
    for (m = 0; m < MAX_MODULE; m++) {
        if (PTM_MODULE_INITCB(g, m)) {
            ret = PTM_MODULE_INITCB(g, m)(g);
            if (ret) {
                /* init failed - retry init */
                fprintf(stderr, "Module %s init failed \n",
                        ptm_module_string(m));
                ptm_g.retry_mods |= (1 << m);
            }
        } else {
            PTM_MODULE_INITIALIZE(g, m);
        }
    }

    if (ptm_g.retry_mods) {
        /* create a timer event to retry failed modules */
        ptm_queue_init_retry_timer();
    }

    atexit(ptmd_exit);

    strcpy(g->topo_file, file);
    LOG("Local host name %s, IP %s\n", g->my_hostname, g->my_mgmtip);
    if (!g->my_hostname || !g->my_mgmtip) {
        DLOG("On init: No local hostname or IP retrieved yet");
        g->conf_init_done = FALSE;
        postpone_init = TRUE;
    }

    if (!postpone_init) {
        ret = ptm_conf_init(g);

        if (ret) {
            /* conf read failed - retry in timer */
            ptm_queue_init_retry_timer();
        } else {
            /* give a chance for each module to populate
             * with current state/data
             */
            for (m = 0; m < MAX_MODULE; m++) {
                /* if a module is pending retry ignore it */
                if (!!(ptm_g.retry_mods & (1 << m)))
                    continue;
                if (PTM_MODULE_POPULATECB(g, m))
                    PTM_MODULE_POPULATECB(g, m)(g);
            }
        }
    }

    ptm_set_signal_handler(SIGUSR1, ptm_sigusr1_cb);
    ptm_set_signal_handler(SIGTERM, ptm_sigterm_cb);
    ptm_set_signal_handler(SIGHUP, ptm_sighup_cb);
    ptm_do_select();

    return (ret);
}
