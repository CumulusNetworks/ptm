/* Copyright 2013,2015 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

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
#define MAX_FD     16

typedef struct _ptm_module_t_ ptm_module_t;
typedef struct _ptm_globals_t_ ptm_globals_t;
typedef struct _ptm_client_t_ ptm_client_t;
typedef struct _ptm_event_t_ ptm_event_t;
typedef enum _ptm_sockevent_e_ ptm_sockevent_e;

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
 * NETLINK_MODULE: to get netlink notifications
 * NBR_MODULE: to get endpoint IP addresses.
 * BFD_MODULE: to generate BFD transactions to all NBR's
 * QUAGGA_MODULE: to generate BFD transactions to all QUAGGA neighbors
 * CTL_MODULE: client connections to PTMD that want to receive
 *             topology status notifications.
 */
typedef enum {
    TIMER_MODULE,
    LLDP_MODULE,
    NETLINK_MODULE,
    NBR_MODULE,
    QUAGGA_MODULE,
    BFD_MODULE,
    CTL_MODULE,
    CONF_MODULE,
    MAX_MODULE,
} ptm_module_e;

enum _ptm_sockevent_e_ {
    SOCKEVENT_READ,
    SOCKEVENT_WRITE,
    MAX_SOCKEVENT,
};

typedef enum {
    MOD_STATE_INITIALIZED,
    MOD_STATE_POPULATE,
    MOD_STATE_ERROR,
    MOD_STATE_RUNNING,
} ptm_module_st_e;

typedef enum {
    BFD_SINGLE_HOP = 1,
    BFD_MULTI_HOP,
} ptm_bfd_type_e;

/* forward reference */
struct ptm_conf_port;

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
typedef int (*ptm_event_cb) (ptm_event_t *event);
typedef int (*ptm_parse_cb) (struct ptm_conf_port *port, char *args);
typedef int (*ptm_init_cb) (ptm_globals_t *g);
typedef int (*ptm_populate_cb) (ptm_globals_t *g);
typedef int (*ptm_process_cb) (int in_fd, ptm_sockevent_e t, void *data);
typedef int (*ptm_status_cb) (void *, void *, void *);

/**
 * The central structure used for topology notification to upper level
 * functions.
 *
 * TODO: should we make the structure hierarchical?
 *
 * @param type: event type
 * @param module: which module sent the notification?
 * @param rname: local system name
 * @param rname: remote system name
 * @param liface: local interface name
 * @param riface: remote interface name
 * @param rdescr: remote interface description
 * @param lmac: local interface's mac address
 * @param rmac: remote interface's mac address
 * @param lmgmtip: local Mgmt IP
 * @param rmgmtip: remote Mgmt IP
 * @param lv6addr: local IPv6 address
 * @param lv4addr: local IPv4 address
 * @param rv6addr: remote IPv6 address
 * @param rv4addr: remote IPv4 address
 * @param bfdtype: bfd session type (multi/single)
 * @param vnid_present: is vnid field valid
 * @param vnid: vnid to be used
 * @param ctxt: caller's private context info
 * @param client: in case this is a client that connected to the control
 *                socket (or sent some data over an existing connection).
 *                If it's a new client, type would be set to EVENT_ADD and
 *                client structure would have been freshly malloc'ed. If it's
 *                an existing client that sent some interesting data, the
 *                type would be set to EVENT_UPD. No EVENT_DEL at the moment.
 * @param vrf_name: VRF name
 * @param vrf_id: VRF id
 */

struct _ptm_event_t_ {
    ptm_event_e      type;
    ptm_module_e     module;
    char             *lname;
    char             *rname;
    char             *liface;
    char             *riface;
    char             *rdescr;
    char             *lmac;
    char             *rmac;
    char             *lmgmtip;
    char             *rmgmtip;
    char             *lv6addr;
    char             *lv4addr;
    char             *rv6addr;
    char             *rv4addr;
    ptm_bfd_type_e   bfdtype;
    uint32_t         vnid_present;
    uint32_t         vnid;
    ptm_client_t     *client;
    void             *ctxt;
    char             *vrf_name;
    uint32_t         vrf_id;
};

/**
 * A structure to represent each module (see ptm_module_e enum).
 * init_cb = handle module initialization
 * parse_cb = handle module specific args specified in topo file
 * populate_cb = populate with current data
 * event_cb = handle events received from external entities (lldpctl, rtnetlink etc)
 * process_cb = handle socket read buffer
 * cmd_cb = handle cmds from external clients that connect to us
 * peer_cb = call peer registered callback when event occurs
 * fd  = socket listening on
 */
struct _ptm_module_t_ {
    ptm_init_cb     init_cb;
    ptm_parse_cb    parse_cb;
    ptm_populate_cb populate_cb;
    ptm_event_cb    event_cb;
    ptm_process_cb  process_cb;
    ptm_status_cb   status_cb;
    ptm_event_cb    peer_cb[MAX_MODULE];
    int             fd[MAX_FD];
    ptm_module_st_e state;
};

typedef enum {
    PTM_INIT,
    PTM_RUNNING,
    PTM_SHUTDOWN,
    PTM_RECONFIG,
    PTM_PAUSED,
} ptm_state_e;

#define PTM_GET_STATE(g) g->ptm_state
#define PTM_SET_STATE(g, s) g->ptm_state = s

#define MAX_FAST_INIT_RETRY_COUNT    5

/**
 * A global structure visible to ptm_event.c as well as all the modules (LLDP,
 * NBR, CTL, ...). Sets itself for easy manipulation of data instead of passing
 * data as parameters to functions.
 */
struct _ptm_globals_t_ {
    ptm_module_t    modules[MAX_MODULE];
    fd_set          masterset;
    fd_set          writeset;
    fd_set          exceptset;
    int             maxfd;
    char            *my_hostname;
    char            *my_mgmtip;
    char            topo_file[MAXNAMELEN+1];
    bool            conf_init_done;
    unsigned int    init_retry_count;
    void            *retry_timer;
    int             retry_interval;
    ptm_state_e     ptm_state;
    void            *ptmlib_hdl;
};

typedef struct _ptm_status_ctxt_s {
    struct ptm_conf_port    *port;
    int                      bfd_get_next;
    char                     bfd_peer[MAXNAMELEN];
    int                      set_env_var;
} ptm_status_ctxt_t;

/**
 * String'ify PTM event type.
 */
static inline const char *
ptm_event_type_str (ptm_event_e type)
{
    switch (type) {
    case EVENT_DEL:
        return "DEL";
        break;
    case EVENT_UPD:
        return "UPDATE";
        break;
    case EVENT_ADD:
        return "ADD";
        break;
    default:
        return "Unknown event";
        break;
    }
}

static inline char *
ptm_module_string (ptm_module_e mod)
{
    char *modstr[] = {"TIMER", "LLDP", "NETLINK", "NBR",
                      "QUAGGA", "BFD", "CTL", "CONF"};
    if (mod < MAX_MODULE) {
        return (modstr[mod]);
    }
    return ("null");
}

#define PTM_MODULE_SET_FD(gbl, sfd, module, i)              \
    do {                                                    \
        if ((sfd) && module < MAX_MODULE && i < MAX_FD) {   \
            (gbl)->modules[module].fd[i] = (sfd);           \
        }                                                   \
        if ((sfd) > 0) {                                    \
            ptm_fd_add((sfd));                              \
        }                                                   \
    } while (0)

#define PTM_MODULE_INITIALIZE(gbl, module)                  \
    do {                                                    \
        int i;                                              \
        memset(&(gbl)->modules[module].parse_cb, 0x00,      \
               (sizeof((gbl)->modules[module]) -            \
                offsetof(struct _ptm_module_t_, parse_cb)));\
        for (i = 0; i < MAX_FD; i++) {                      \
            (gbl)->modules[module].fd[i] = -1;              \
        }                                                   \
    } while (0)
#define PTM_MODULE_FD(gbl, module, i)    (gbl)->modules[module].fd[i]
#define PTM_MODULE_INITCB(gbl, module) (gbl)->modules[module].init_cb
#define PTM_MODULE_EVENTCB(gbl, module) (gbl)->modules[module].event_cb
#define PTM_MODULE_POPULATECB(gbl, module) (gbl)->modules[module].populate_cb
#define PTM_MODULE_PROCESSCB(gbl, module) (gbl)->modules[module].process_cb
#define PTM_MODULE_PARSECB(gbl, module) (gbl)->modules[module].parse_cb
#define PTM_MODULE_STATUSCB(gbl, module) (gbl)->modules[module].status_cb
#define PTM_MODULE_PEERCB(gbl, module, peer) (gbl)->modules[peer].peer_cb[module]

#define PTM_MODULE_SET_STATE(gbl, module, st) (gbl)->modules[module].state = st
#define PTM_MODULE_GET_STATE(gbl, module) (gbl)->modules[module].state

/**
 * String'ify PTM event structure.
 */
char *ptm_event_str(ptm_event_t *event);
void ptm_event_cleanup(ptm_event_t *event);
void ptm_fd_cleanup(int fd);
void ptm_fd_add (int fd);
ptm_event_t * ptm_event_clone(ptm_event_t *event);
void ptm_module_handle_event_cb(ptm_event_t *event);
void ptm_module_request_reinit();

#endif
