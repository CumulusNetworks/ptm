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
#include "ptm_lldp.h"
#include "ptm_ctl.h"
#include "ptm_conf.h"
#include "ptm_timer.h"
#include "csv.h"
#include "ptm_msg.h"

static FILE *fp;

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

static void
ptmd_exit (void)
{
    ptm_conf_finish ();
    ptm_finish_lldp ();
    INFOLOG("PTMD exiting.\n");
    fclose(fp);
    _exit(0);
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

/**
 * Cleanup the fields of an event structure.
 */
void
ptm_event_cleanup (ptm_event_t *event)
{
    if (!event) {
        return;
    }
    if (event->lname) {
        free(event->lname);
    }
    if (event->rname) {
        free(event->rname);
    }
    if (event->liface) {
        free(event->liface);
    }
    if (event->riface) {
        free(event->riface);
    }
    if (event->lmac) {
        free(event->lmac);
    }
    if (event->rmac) {
        free(event->rmac);
    }
    if (event->lmgmtip) {
        free(event->lmgmtip);
    }
    if (event->rmgmtip) {
        free(event->rmgmtip);
    }
    if (event->rv6addr) {
        free(event->rv6addr);
    }
    if (event->rv4addr) {
        free(event->rv4addr);
    }
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

ptm_globals_t ptm_g = { { NULL,
                          ptm_conf_process_nbr_update,
                          NULL,
                          ptm_conf_process_new_client,
                          NULL},
                        {
                          { cl_timer_init,
                            NULL,
                            cl_timer_expired,
                            -1 },
                          { ptm_init_lldp,
                            ptm_populate_lldp,
                            ptm_process_lldp,
                            -1 },
                          { NULL,/*ptm_init_nbr,*/
                            NULL,
                            NULL,/*ptm_process_nbr,*/
                            -1 },
                          { ptm_init_ctl,
                            NULL,
                            ptm_process_ctl,
                            -1 },
                          { NULL,/*ptm_conf_init,*/
                            NULL,
                            NULL,/*ptm_conf_process_file_event,*/
                            -1 },
                        },
                      };

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

static int
ptm_do_select ()
{
    fd_set workset;
    fd_set wrset;
    int retval;
    int m;
    int i;
    ptm_globals_t *g = &ptm_g;

    FD_ZERO(&ptm_g.writeset);
    FD_ZERO(&ptm_g.masterset);
    ptm_g.maxfd = 0;
    for (m = 0; m < MAX_MODULE; m++) {
        if (g->modules[m].fd != -1) {
            FD_SET(g->modules[m].fd, &g->masterset);
            if (g->modules[m].fd > g->maxfd) {
                g->maxfd = g->modules[m].fd;
            }
        }
    }

    while (1) {
        memcpy(&workset, &g->masterset, sizeof(g->masterset));
        memcpy(&wrset, &g->writeset, sizeof(g->writeset));

        retval = select(g->maxfd+1, &workset, &wrset, NULL, NULL);

        if (retval == -1) {
            if (errno == EINTR) continue;
            else {
                ERRLOG("select() error (%s)\n", strerror(errno));
                return (-1);
            }
        }
        if (retval == 0) continue;

        for (i = 0; i <= g->maxfd; i++) {

            if (FD_ISSET(i, &workset)) {
                m = _fd_to_module(i);
                DLOG("%s: FD %d READSET FOR MODULE %s\n", __FUNCTION__, i,
                    ptm_module_string(m));
                if (g->modules[m].process_cb) {
                    g->modules[m].process_cb(i, SOCKEVENT_READ, NULL);
                }
            }

            if (FD_ISSET(i, &wrset)) {
                m = _fd_to_module(i);
                DLOG("%s: FD %d WRITESET FOR MODULE %s\n", __FUNCTION__, i,
                    ptm_module_string(m));
                if (g->modules[m].process_cb) {
                    g->modules[m].process_cb(i, SOCKEVENT_WRITE, NULL);
                }
            }
        }
    }
    return (0);
}

static void
ptm_sigusr1_cb (int signum)
{
    ptm_conf_reparse_topology();
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

int
main (int argc, char *argv[])
{
    ptm_globals_t *g = &ptm_g;
    int ret;
    int ch;
    const char logfile[] = "/var/log/ptmd.log";
    char file[MAXNAMELEN];
    int m;
    bool daemonize = FALSE;
    const char *PIDPATH = "/var/run/ptmd.pid";
    char loglevel[16] = "INFO";
    char tmplogstr[MAXNAMELEN+16];
    const char *logstr[2];

    sprintf(file, "%s/%s", PTM_CONF_DIR, PTM_CONF_FILE);
    while ((ch = getopt(argc, argv, "dhc:l:")) != -1) {
        switch(ch) {
        case 'c':
            strcpy(file, optarg);
            break;
        case 'd':
            daemonize = TRUE;
            break;
        case 'l':
            strncpy(loglevel, optarg, 16);
            break;
        case 'h':
        default:
            ptmd_usage(argv[0]);
            break;
        }
    }

    /*
     * Check to see if another ptmd is running.
     */
    if ((fp = fopen(PIDPATH, "a+")) == NULL) {
        fprintf(stderr, "Couldn't write pid file %s\n", PIDPATH);
        exit (1);
    } else {
        /* Use file locking to ensure we're the only instance */
        /* XXX: Use lockf() if ported to other platforms */
        /* Using flock as it works across daemon() call */
        if (flock(fileno(fp), LOCK_EX | LOCK_NB) < 0) {
            fprintf(stderr, "Another instance of ptmd running? (err=%s)\n",
                    strerror(errno));
            exit(1);
        }
    }

    sprintf(tmplogstr, "file:%s=%s", logfile, loglevel);
    logstr[0] = strdupa(tmplogstr);
    ret = log_init(logstr, 1);
    if (!ret) {
        fprintf(stderr, "Log init failed, exiting.\n");
        exit(11);
    }

    if (daemonize)
        daemon(0, 0);

    /* The PID will now be right */
    ftruncate(fileno(fp), 0);
    fprintf(fp, "%d\n", getpid());

    for (m = 0; m < MAX_MODULE; m++) {
        if (g->modules[m].init_cb) {
            g->modules[m].init_cb(g);
        }
    }

    atexit(ptmd_exit);

    strcpy(g->topo_file, file);
    LOG("Local host name %s, IP %s\n", g->my_hostname, g->my_mgmtip);
    if (!g->my_hostname && !g->my_mgmtip) {
        DLOG("On init: No local hostname or IP retrieved yet");
        g->conf_init_done = false;
    } else
        ptm_conf_init(g);

    for (m = 0; m < MAX_MODULE; m++) {
        if (g->modules[m].fill_cb) {
            g->modules[m].fill_cb(g);
        }
    }

    ptm_set_signal_handler(SIGUSR1, ptm_sigusr1_cb);
    ptm_set_signal_handler(SIGTERM, ptm_sigterm_cb);
    ptm_set_signal_handler(SIGHUP, ptm_sighup_cb);
    ptm_do_select();

    return (ret);
}
