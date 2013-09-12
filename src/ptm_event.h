/* Copyright 2013 Cumulus Networks, LLC.  All rights reserved. */

#ifndef _PTM_EVENT_H_
#define _PTM_EVENT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>

#define MAXNAMELEN 255

typedef struct _ptm_module_t_ ptm_module_t;
typedef struct _ptm_globals_t_ ptm_globals_t;
typedef struct _ptm_client_t_ ptm_client_t;
typedef struct _ptm_event_t_ ptm_event_t;
typedef enum _ptm_sockevent_e_ ptm_sockevent_e;

/**
 * Upstream callback function that should get called for each neighbor/
 * topology event.
 *
 * For PTM topology verification, this will be the function that
 * matches the "actual/operational" topology information (as provided in
 * ptm_event_t) with the "admin-provided/prescribed" topology information.
 * It would then take some actions based on that match - log and/or notify.
 *
 * \param event: pointer to the notification event structure. Note: the
 *               memory for the event comes out of a global structure and
 *               will get overwritten once the callback returns. So copy
 *               it to new memory if you want to reuse.
 */
typedef void (*ptm_event_cb) (ptm_event_t *event);

typedef int (*ptm_init_module_cb) (ptm_globals_t *g);

typedef int (*ptm_populate_module_cb) ();

typedef int (*ptm_process_cb) (int in_fd, ptm_sockevent_e t, void *data);

typedef int (*ptm_term_module_cb) (int fd);

enum _ptm_exitcodes_e_ {
    PTM_EXITCODE_NO_LLDPD = -11,
    PTM_EXITCODE_NO_MEMORY = -12,
    PTM_EXITCODE_IRFAILURE = -13,
};

/**
 * Possible events for a notification.
 */
typedef enum {
    EVENT_ADD,
    EVENT_DEL,
    EVENT_UPD,
    EVENT_UNKNOWN
} ptm_event_e;

/**
 * List of all the modules that are part of PTM.
 * LLDP_MODULE: to get link level details.
 * NBR_MODULE: to get endpoint IP addresses.
 * CTL_MODULE: client connections to PTMD that want to receive
 *             topology status notifications.
 */
typedef enum {
    TIMER_MODULE,
    LLDP_MODULE,
    NBR_MODULE,
    CTL_MODULE,
    CONF_MODULE,
    MAX_MODULE,
} ptm_module_e;

#define PTM_MODULE_EVENT_LLDP  0x1
#define PTM_MODULE_EVENT_NBR   0x2
#define PTM_MODULE_EVENT_CTL   0x4

enum _ptm_sockevent_e_ {
    SOCKEVENT_READ,
    SOCKEVENT_WRITE,
    MAX_SOCKEVENT,
};

/**
 * The central structure used for topology notification to upper level
 * functions.
 *
 * TODO: should we make the structure hierarchical?
 *
 * @param type: event type
 * @param module: which module sent the notification?
 * @param rname: remote system name
 * @param riface: remote interface name
 * @param liface: local interface name
 * @param rmac: remote interface's mac address
 * @param lmac: local interface's mac address
 * @param rv6addr: remote IPv6 address
 * @param rv4addr: remote IPv4 address
 * @param client: in case this is a client that connected to the control
 *                socket (or sent some data over an existing connection).
 *                If it's a new client, type would be set to EVENT_ADD and
 *                client structure would have been freshly malloc'ed. If it's
 *                an existing client that sent some interesting data, the
 *                type would be set to EVENT_UPD. No EVENT_DEL at the moment.
 */
struct _ptm_event_t_ {
    ptm_event_e      type;
    ptm_module_e     module;
    char             *lname;
    char             *rname;
    char             *liface;
    char             *riface;
    char             *lmac;
    char             *rmac;
    char             *lmgmtip;
    char             *rmgmtip;
    char             *rv6addr;
    char             *rv4addr;
    ptm_client_t     *client;
};

/**
 * A structure to represent each module (see ptm_module_e enum). Each module
 * has an init routine, a process routine, and the parent fd it created. The
 * main routine in ptm_event.c takes these fds to set up the select() fdset
 * and blocks on the select() call. When select() returns, it figure out the
 * corresponding module and calls its process_cb routine.
 */
struct _ptm_module_t_ {
    ptm_init_module_cb     init_cb;
    ptm_populate_module_cb fill_cb;
    ptm_process_cb         process_cb;
    int                    fd;
};

/**
 * A global structure visible to ptm_event.c as well as all the modules (LLDP,
 * NBR, CTL, ...). Sets itself for easy manipulation of data instead of passing
 * data as parameters to functions.
 */
struct _ptm_globals_t_ {
    ptm_event_cb       event_cb[MAX_MODULE];
    ptm_module_t       modules[MAX_MODULE];
    fd_set             masterset;
    fd_set             writeset;
    fd_set             exceptset;
    int                maxfd;
    char               *my_hostname;
    char               *my_mgmtip;
    char               topo_file[MAXNAMELEN+1];
    bool              hostname_changed;
    bool              mgmt_ip_changed;
    bool              conf_init_done;
};

/**
 * String'ify PTM event type.
 */
static inline const char *
ptm_event_type_str (ptm_event_e type)
{
    switch (type) {
    case EVENT_DEL:
        return "Delete";
        break;
    case EVENT_UPD:
        return "Update";
        break;
    case EVENT_ADD:
        return "Add";
        break;
    default:
        return "Unknown event";
        break;
    }
}

static inline const char *
ptm_module_string (ptm_module_e mod)
{
    const char *modstr[] = {"TIMER", "LLDP", "NBR", "CTL", "CONF"};
    if (mod < MAX_MODULE) {
        return (modstr[mod]);
    }
    return ("null");
}

#define PTM_MODULE_SET_FD(gbl, sfd, module)      \
    do {                                         \
        if ((sfd) && module < MAX_MODULE) {      \
            (gbl)->modules[module].fd = (sfd);   \
        }                                        \
    } while (0)

#define PTM_MODULE_FD(gbl, module)    (gbl)->modules[module].fd

#define PTM_MODULE_EVENTCB(gbl, module) (gbl)->event_cb[module]

#define PTM_MODULE_POPULATECB(gbl, module) (gbl)->modules[module].fill_cb

/**
 * String'ify PTM event structure.
 */
char *ptm_event_str(ptm_event_t *event);

void ptm_event_cleanup(ptm_event_t *event);

void ptm_fd_cleanup(int fd);

void ptm_fd_add (int fd);

#endif
