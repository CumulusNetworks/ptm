/*********************************************************************
 * Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * ptm_lldp.[ch] contain the code that interacts with LLDPD over
 * the LLDPCTL interface, extract the required information,
 * translate them to ptm_event_t abstraction, and call the
 * registered callback for each notification.
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "ptm_event.h"
#include "ptm_timer.h"
#include "ptm_conf.h"
#include "ptm_lib.h"
#include "ptm_lldp.h"
#include "ptm_ctl.h"
#include "lldpctl.h"
#include "lldp-const.h"
#include "log.h"

static int lldp_parse_match_type(lldp_parms_t *parms, char *val);
static int lldp_parse_match_hostname(lldp_parms_t *parms, char *val);
static int ptm_populate_lldp ();
static int ptm_process_lldp (int in_fd, ptm_sockevent_e se, void *udata);
static int ptm_parse_lldp(struct ptm_conf_port *port, char *args);
static int ptm_status_lldp(void *, void *, void *);
static int ptm_lldp_sync_nbrs(void);
static lldp_cache_port *ptm_lldp_alloc_cache_lport(char *, lldpctl_atom_t *,
                                                   ptm_event_t *);
static int ptm_lldp_build_cache_lport_list(void);
static void ptm_lldp_free_cache_lport(lldp_cache_port *);
static void ptm_lldp_free_cache_lport_by_liface(char *);
static void ptm_lldp_free_cache_lport_list(void);
static void ptm_lldp_free_non_existent_ports(void);

//#define LLDPCTL_DEBUG 1

#ifdef LLDPCTL_DEBUG
void ptm_lldpctl_log(int severity, const char *msg);
#else
void ptm_lldpctl_log(int severity, const char *msg) {}
#endif

lldp_parms_hash_t *lldp_parms_hash = NULL;

lldp_parms_key_t lldp_parms_key[] = {
        { .key = "match_type", .key_cb = lldp_parse_match_type },
        { .key = "match_hostname", .key_cb = lldp_parse_match_hostname },
        { .key = NULL, .key_cb = NULL},
};

match_type_list type_list[] = {
        { .str = "portdescr", .type = PORT_DESCRIPTION},
        { .str = "ifname", .type = PORTID_IFNAME},
        { .str = NULL },
};

match_hostname_list hostname_list[] = {
        { .str = "hostname", .type = PTM_HOST_NAME_TYPE_HOSTNAME},
        { .str = "fqdn", .type = PTM_HOST_NAME_TYPE_FQDN},
        { .str = NULL },
};

char *LLDP_TEMPLATE_KEY = "lldptmpl";

#define MOD_LLDP_RETRY_COUNT  5

#define LLDP_MAX_IFACE_PER_LOOP 20
/* LLDP iface processing interval */
#define LLDP_IFACE_INTERVAL (100 * NSEC_PER_MSEC)

/**
 * Global structure (private to this file) for bookkeeping - init params,
 * input params, statistics, and such.
 */
typedef struct {
    lldpctl_conn_t  *conn;
    ptm_globals_t   *gbl;
    ptm_event_t     event;
    int             resync;
    int             in_cache_loop;
    void            *iface_timer;
    lldp_parms_t    parms;
    unsigned int    mod_retry_cnt;
    char            err_str[256];
} ptm_lldp_globals_t;

ptm_lldp_globals_t ptm_lldp;

lldp_port *lldp_port_hash = NULL;
lldp_cache_port *lldp_port_cache_hash = NULL;

cl_timer_t *ptm_timer_cb_lldp(cl_timer_t *timer, void *context);

static inline ptm_event_e
lldp_type_to_ptm_event_type (lldpctl_change_t type)
{
    switch (type) {
    case lldpctl_c_deleted:
        return (EVENT_DEL);
        break;
    case lldpctl_c_updated:
        return (EVENT_UPD);
        break;
    case lldpctl_c_added:
        return (EVENT_ADD);
        break;
    default:
        return (EVENT_UNKNOWN);
        break;
    }
}

/**
 * Extract information from the LLDP atoms to a generic structure -
 * ptm_event_t.
 * Carefully check any lldpctl call you add. If it requests data from
 * lldpd daemon, the send/recv request can clobber existing data. For
 * example, call to lldpctl_get_port() in this routine resulted in
 * watch_cb being called in a nested fashion causing errors.
 * we only care for LLDP events - all other protocols are ignored
 */
static int
_extract_event (ptm_event_t *event,
                ptm_event_e type,
                lldpctl_atom_t *interface,
                lldpctl_atom_t *neighbor)
{
    lldpctl_atom_t *mgmts, *mgmt;
    const char *lldp_str;
    const char *buf;

    if (!event || !interface || !neighbor || (type >= EVENT_UNKNOWN)) {
        ERRLOG("%s: Unknown event/if/nbr/type\n", __FUNCTION__);
        return (-1);
    }

    /* check if neighbor talks LLDP */
    lldp_str = lldpctl_atom_get_str(neighbor, lldpctl_k_port_protocol);

    if (strcmp(lldp_str, "LLDP")){
        DLOG("%s: Expected (LLDP) != Recd (%s) - dropping event \n",
                __FUNCTION__, lldp_str);
        return (-1);
    }

    event->type = type;
    event->module = LLDP_MODULE;
    buf = lldpctl_atom_get_str(interface, lldpctl_k_interface_name);
    if (buf)
        event->liface = strdup(buf);
    buf = lldpctl_atom_get_str(neighbor, lldpctl_k_port_id);
    if (buf)
        event->riface = strdup(buf);
    buf = lldpctl_atom_get_str(neighbor, lldpctl_k_port_descr);
    /* Port Descr TLV is not mandatory and can be NULL */
    if (buf)
        event->rdescr = strdup(buf);
    buf = lldpctl_atom_get_str(neighbor, lldpctl_k_chassis_name);
    if (buf)
        event->rname = strdup(buf);
    if (lldpctl_atom_get_int(neighbor, lldpctl_k_port_id_subtype) ==
        LLDP_PORTID_SUBTYPE_LLADDR) {
        buf = lldpctl_atom_get_str(neighbor, lldpctl_k_port_id);
        if (buf)
            event->rmac = strdup(buf);
    }
    mgmts = mgmt = NULL;
    mgmts = lldpctl_atom_get(neighbor, lldpctl_k_chassis_mgmt);
    lldpctl_atom_foreach(mgmts, mgmt) {
        buf = lldpctl_atom_get_str(mgmt, lldpctl_k_mgmt_ip);
        if (buf)
            event->rmgmtip = strdup(buf);
        break;
    }

    if (mgmt)
        lldpctl_atom_dec_ref(mgmt);
    if (mgmts)
        lldpctl_atom_dec_ref(mgmts);

    return (0);
}

/**
 * Routine to handle LLDP event data
 * If data=1    - called by lldpctl to notify about a change
 * If data=NULL - called by ptm internally
 */
static void
process_lldp_neighbors_cb (lldpctl_conn_t *conn,
                           lldpctl_change_t type,
                           lldpctl_atom_t *interface,
                           lldpctl_atom_t *neighbor,
                           void *data)
{
    ptm_event_t *ev;
    int lldp_notify = (data)?1:0;

    if (!_extract_event(&ptm_lldp.event, lldp_type_to_ptm_event_type(type),
                        interface, neighbor)) {
        if (ptm_lldp.event.liface &&
            ptm_lldp.event.rname &&
            (ptm_lldp.event.riface || ptm_lldp.event.rdescr)) {
            if (lldp_notify && ptm_lldp.in_cache_loop) {
                /* we are in cache loop, and this is a lldpctl notification
                 * add this event to the cache list, we will process it later
                 */
                ev = ptm_event_clone(&ptm_lldp.event);
                INFOLOG("LLDP %s for iface %s - add to cache\n",
                        ptm_event_type_str(ev->type), ptm_lldp.event.liface);
                /* grab a reference */
                lldpctl_atom_inc_ref(interface);
                ptm_lldp_alloc_cache_lport(ptm_lldp.event.liface,
                                           interface, ev);
            } else {
                /* not a lldp notification
                 * OR
                 * not in cache loop
                 */
                if (!ptm_lldp.in_cache_loop) {
                    /* remove from cache if present */
                    ptm_lldp_free_cache_lport_by_liface(ptm_lldp.event.liface);
                }
                /* process the event */
                ptm_module_handle_event_cb(&ptm_lldp.event);
            }
        } else {
            if (!ptm_lldp.event.liface) {
                ERRLOG("%s: local iface not set\n", __FUNCTION__);
            } else if (!ptm_lldp.event.rname) {
                ERRLOG("%s: remote sysname not set\n", __FUNCTION__);
            } else if (!ptm_lldp.event.riface || !ptm_lldp.event.rdescr) {
                ERRLOG("%s: remote iface/port descr not set\n", __FUNCTION__);
            }
        }
    }
    ptm_event_cleanup(&ptm_lldp.event);
}

static int
process_cache_lport(lldp_cache_port *cache_lport)
{
    lldpctl_conn_t  *conn = ptm_lldp.conn;
    lldpctl_atom_t *port = NULL;
    lldpctl_atom_t *neighbors = NULL;
    lldpctl_atom_t *neighbor = NULL;
    char liface[MAXNAMELEN+1];

    strcpy(liface, cache_lport->liface);

    /* if event is available , use it */
    if (cache_lport->ev) {
        ptm_module_handle_event_cb(cache_lport->ev);
        ptm_event_cleanup(cache_lport->ev);
        cache_lport->ev = NULL;
        return 0;
    }

    port = lldpctl_get_port(cache_lport->iface);

    /* its possible that during the lldpctl_get_port call
     * this cache_lport got updated with an event
     * we check to see if it got a new "event" reference
     */
    if (cache_lport->ev) {
        ptm_module_handle_event_cb(cache_lport->ev);
        ptm_event_cleanup(cache_lport->ev);
        cache_lport->ev = NULL;
        return 0;
    }

    /* no new event, just process like a regular lport */

    if (port == NULL) {
        INFOLOG("No lldp port for iface %s - lldpctl[%s]\n",
                liface, lldpctl_last_strerror(conn));
        return 0;
    }

    /* sanity check returned data */
    if (strcmp(lldpctl_atom_get_str(port, lldpctl_k_port_name), liface)) {
        ERRLOG("%s: lldpctl error - portname [%s] != liface [%s]\n",
                __FUNCTION__,
                lldpctl_atom_get_str(port, lldpctl_k_port_name),
                liface);
        lldpctl_atom_dec_ref(port);
        return -1;
    }

    neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);
    lldpctl_atom_foreach(neighbors, neighbor) {
        process_lldp_neighbors_cb(conn, lldpctl_c_added,
                                  cache_lport->iface, neighbor, NULL);
    }
    if (neighbors)
        lldpctl_atom_dec_ref(neighbors);
    if (port)
        lldpctl_atom_dec_ref(port);

    return 0;
}

static void
ptm_lldp_iface_timer (cl_timer_t *timer,
                      void *context)
{
    int ret;

    ptm_lldp.in_cache_loop = 1;

    ret = ptm_lldp_sync_nbrs();

    ptm_lldp.in_cache_loop = 0;

    if (ret) {
        sprintf(ptm_lldp.err_str, "%s: LLDPCTL sync failed - retry",
            __FUNCTION__);
        ptm_shutdown_lldp();
    }
}

/* routine used to arm (or re-arm) the iface timer */
static void
ptm_lldp_queue_iface_timer()
{
    if (!ptm_lldp.iface_timer) {
        ptm_lldp.iface_timer = cl_timer_create();
        cl_timer_arm(ptm_lldp.iface_timer, ptm_lldp_iface_timer,
                     LLDP_IFACE_INTERVAL,
                     (T_UF_PERIODIC | T_UF_NSEC));
    }
}

static void
ptm_lldp_free_iface_timer()
{
    if (ptm_lldp.iface_timer) {
        cl_timer_destroy(ptm_lldp.iface_timer);
        ptm_lldp.iface_timer = NULL;
    }
}

static void
ptm_lldp_free_cache_lport(lldp_cache_port *cache_lport)
{
    HASH_DELETE(pch, lldp_port_cache_hash, cache_lport);
    if (cache_lport->ev)
        ptm_event_cleanup(cache_lport->ev);
    if (cache_lport->iface)
        lldpctl_atom_dec_ref(cache_lport->iface);
    free(cache_lport);
}

static void
ptm_lldp_free_cache_lport_by_liface(char *liface)
{
    lldp_cache_port *cache_lport;
    HASH_FIND(pch, lldp_port_cache_hash, liface,
              strlen(liface), cache_lport);
    if (cache_lport)
        ptm_lldp_free_cache_lport(cache_lport);
}

static void
ptm_lldp_free_cache_lport_list(void)
{
    lldp_cache_port *cache_lport, *tmp;

    DLOG("%s: free lldp cache\n", __FUNCTION__);

    HASH_ITER(pch, lldp_port_cache_hash, cache_lport, tmp) {
        ptm_lldp_free_cache_lport(cache_lport);
    }
}

/* allocate a lldp cache port struct */
static lldp_cache_port *
ptm_lldp_alloc_cache_lport(char *liface, lldpctl_atom_t *iface,
                           ptm_event_t *ev)
{
    lldp_cache_port *cache_lport;

    HASH_FIND(pch, lldp_port_cache_hash, liface, strlen(liface), cache_lport);

    if (cache_lport) {
        if (cache_lport->iface != iface) {
            /* remove old reference */
            lldpctl_atom_dec_ref(cache_lport->iface);
        }
        cache_lport->iface = iface;
        if ((cache_lport->ev) &&
            (cache_lport->ev != ev)) {
            /* remove old event struct */
            ptm_event_cleanup(cache_lport->ev);
        }
        cache_lport->ev = ev;
        return cache_lport;
    }

    cache_lport = calloc(1, sizeof(*cache_lport));

    if (cache_lport) {
        strcpy(cache_lport->liface, liface);
        cache_lport->iface = iface;
        cache_lport->ev = ev;
        HASH_ADD(pch, lldp_port_cache_hash, liface,
                 strlen(liface), cache_lport);
    }

    return cache_lport;
}

static int
ptm_lldp_build_cache_lport_list(void)
{
    lldpctl_conn_t *conn = ptm_lldp.conn;
    lldpctl_atom_t *iface_list = NULL;
    lldpctl_atom_t *iface = NULL;
    lldpctl_atom_iter_t *iter = NULL;
    lldp_cache_port *cache_lport;
    char liface[MAXNAMELEN+1];

    DLOG("%s: build lldp cache\n", __FUNCTION__);

    /* first free up the previous cache list */
    ptm_lldp_free_cache_lport_list();

    iface_list = lldpctl_get_interfaces(conn);
    if (!iface_list) {
        ERRLOG("No iface list from LLDP - lldpctl[%s]\n",
                lldpctl_last_strerror(conn));
        return (-1);
    }
    iter = lldpctl_atom_iter(iface_list);

    /* run through all the lldp interfaces
     * and create a cache lport per interface
     */
    while (iter != NULL) {
        iface = lldpctl_atom_iter_value(iface_list, iter);
        iter = lldpctl_atom_iter_next(iface_list, iter);
        strcpy(liface, lldpctl_atom_get_str(iface, lldpctl_k_interface_name));
        if (!ptm_conf_get_port_by_name(liface)) {
            /* this port not configured in topo file */
            DLOG("%s: topo port not present for iface %s\n",
                    __FUNCTION__, liface);
            lldpctl_atom_dec_ref(iface);
            continue;
        }

        /* allocate a cached lport */
        cache_lport = ptm_lldp_alloc_cache_lport(liface, iface, NULL);
        if (!cache_lport) {
            ERRLOG("%s: No l_port allocated for iface %s\n",
                   __FUNCTION__, liface);
            lldpctl_atom_dec_ref(iface);
            continue;
        }
    }
    lldpctl_atom_dec_ref(iface_list);

    return 0;
}

/**
 * sync info from LLDPD.
 */
static int
ptm_lldp_sync_nbrs(void)
{
    lldpctl_conn_t *conn = ptm_lldp.conn;
    lldpctl_atom_t *config;
    lldp_cache_port *cache_lport, *tmp;
    char liface[MAXNAMELEN+1];
    int iface_processed = 0;
    int done = FALSE;

    if (!conn) {
        return (-1);
    }

    INFOLOG("%s: sync lldp nbrs\n", __FUNCTION__);

    config = lldpctl_get_configuration(conn);
    if (config == NULL) {
        ERRLOG("lldpctl_get_configuration failed - lldpctl[%s]\n",
               lldpctl_last_strerror(conn));
        return (-1);
    }
    if (lldpctl_atom_get_int(config, lldpctl_k_config_paused)) {
        lldpctl_atom_dec_ref(config);
        INFOLOG("%s : LLDP is paused\n", __FUNCTION__);
        return (-1);
    }
    lldpctl_atom_dec_ref(config);

    /* do we need to re-sync with lldp? */
    if (ptm_lldp.resync) {
        if (ptm_lldp_build_cache_lport_list() < 0) {
            return (-1);
        }
        ptm_lldp.resync = FALSE;
    }

    /* process cache lports */
    while (!done) {

        HASH_ITER(pch, lldp_port_cache_hash, cache_lport, tmp) {break;}

        if (!cache_lport) {
            done = TRUE;
            break;
        }

        /* make copy of in-process liface */
        strcpy(liface, cache_lport->liface);

        if (process_cache_lport(cache_lport) == 0) {
            iface_processed++;

            /* delete the cache copy (if still present) */
            HASH_FIND(pch, lldp_port_cache_hash, liface,
                      strlen(liface), cache_lport);
            if (cache_lport)
                ptm_lldp_free_cache_lport(cache_lport);
        }

        if (iface_processed >= LLDP_MAX_IFACE_PER_LOOP) {
            INFOLOG("%d LLDP entries processed - defer\n",
                    iface_processed);
            ptm_lldp_queue_iface_timer();
            return (0);
        }
    }

    if (!HASH_CNT(pch, lldp_port_cache_hash)) {
        /* if we got here, then we finished processing cache list */
        ptm_lldp_free_iface_timer();

        /* clean up lports that dont have ptm ports */
        ptm_lldp_free_non_existent_ports();
    }

    return(0);
}

/**
 * Get the local host name and mgmt IP address.
 */
static int
get_local_params (lldpctl_conn_t *conn)
{
    lldpctl_atom_t *iface_list = NULL;
    lldpctl_atom_t *iface = NULL;
    lldpctl_atom_t *port = NULL;
    lldpctl_atom_t *mgmts = NULL;
    lldpctl_atom_t *mgmt = NULL;
    lldpctl_atom_iter_t *iter = NULL;
    lldpctl_atom_t *config;
    int found = 0;
    const char *buf;

    config = lldpctl_get_configuration(conn);
    if (config == NULL) {
        ERRLOG("lldpctl_get_configuration failed - lldpctl[%s]\n",
                lldpctl_last_strerror(conn));
        return (-1);
    }
    if (lldpctl_atom_get_int(config, lldpctl_k_config_paused)) {
        lldpctl_atom_dec_ref(config);
        INFOLOG("%s : LLDP is paused\n", __FUNCTION__);
        return (-1);
    }
    lldpctl_atom_dec_ref(config);
    iface_list = lldpctl_get_interfaces(conn);
    if (!iface_list) {
        ERRLOG("lldpctl_get_interfaces failed - lldpctl[%s]\n",
               lldpctl_last_strerror(conn));
        return (-1);
    }

    iter = lldpctl_atom_iter(iface_list);
    while (iter != NULL) {
        iface = lldpctl_atom_iter_value(iface_list, iter);
        port = lldpctl_get_port(iface);
        if (port == NULL) {
            ERRLOG("No lldp port for iface %s - lldpctl[%s]\n",
                   lldpctl_atom_get_str(iface, lldpctl_k_interface_name),
                   lldpctl_last_strerror(conn));
            lldpctl_atom_dec_ref(iface);
            iter = lldpctl_atom_iter_next(iface_list, iter);
            continue;
        }
        mgmts = mgmt = NULL;
        buf = lldpctl_atom_get_str(port, lldpctl_k_chassis_name);
        if (buf) {
            ptm_lldp.gbl->my_hostname = strdup(buf);
            mgmts = lldpctl_atom_get(port, lldpctl_k_chassis_mgmt);
            lldpctl_atom_foreach(mgmts, mgmt) {
                buf = lldpctl_atom_get_str(mgmt, lldpctl_k_mgmt_ip);
                if (buf) {
                    ptm_lldp.gbl->my_mgmtip = strdup(buf);
                    found = 1;
                    break;
                }
            }
        }
        if (mgmt)
            lldpctl_atom_dec_ref(mgmt);
        if (mgmts)
            lldpctl_atom_dec_ref(mgmts);

        lldpctl_atom_dec_ref(iface);
        lldpctl_atom_dec_ref(port);

        break;
    }
    lldpctl_atom_dec_ref(iface_list);

    if (found) {
        return (0);
    } else {
        return (-1);
    }
}

void
ptm_shutdown_lldp ()
{
    lldp_port *l_port, *tmp;

    if (strlen(ptm_lldp.err_str)) {
        INFOLOG("Shutting down LLDP socket [%s]\n", ptm_lldp.err_str);
    }

    if (ptm_lldp.conn) {
        lldpctl_release(ptm_lldp.conn);
        ptm_lldp.conn = NULL;
    }

    /* If select set readfd which then returned 0, ensure we remove
     *  this fd from the select list, or we get into an infinite loop
     *  with select waking us up again and again.
     */
    ptm_fd_cleanup(PTM_MODULE_FD(ptm_lldp.gbl, LLDP_MODULE, 0));
    PTM_MODULE_SET_FD(ptm_lldp.gbl, -1, LLDP_MODULE, 0);

    HASH_ITER(ph, lldp_port_hash, l_port, tmp) {
        HASH_DELETE(ph, lldp_port_hash, l_port);
        free(l_port);
    }

    ptm_lldp_free_cache_lport_list();

    if (ptm_lldp.gbl->my_hostname) {
        free(ptm_lldp.gbl->my_hostname);
        ptm_lldp.gbl->my_hostname = NULL;
    }

    if (ptm_lldp.gbl->my_mgmtip) {
        free(ptm_lldp.gbl->my_mgmtip);
        ptm_lldp.gbl->my_mgmtip = NULL;
    }

    ptm_lldp_free_iface_timer();

    PTM_MODULE_SET_STATE(ptm_lldp.gbl, LLDP_MODULE, MOD_STATE_ERROR);
    /* request a re-init */
    ptm_lldp.mod_retry_cnt++;
    ptm_module_request_reinit();
}

/**
 * LLDPD control socket send routine passed to lldpctl, through lldpctl_new
 * See lldpctl.h for definition
 */
static ssize_t
ptm_lldp_send_cb (lldpctl_conn_t *conn,
                  const uint8_t *data,
                  size_t length,
                  void *user_data)
{
    int fd = PTM_MODULE_FD(ptm_lldp.gbl, LLDP_MODULE, 0);
    int each_len = 0;
    int rc;
    int retries = 0;

    while (each_len != length) {
        rc = send(fd, (data + each_len), (length - each_len), MSG_NOSIGNAL);
        if (rc < 0) {
            if (errno != EAGAIN) {
                ERRLOG("fatal send error(%s) - should close connection\n",
                       strerror(errno));
                return (-1);
            }

            if (retries++ < 5) {
                usleep(2000);
                continue;
            }
            return (each_len);
        } else {
            each_len += rc;
            retries = 0;
        }
    }
    return (each_len);
}

/**
 * LLDPD control socket receive routine passed to lldpctl, through lldpctl_new
 * See lldpctl.h for definition. This call is weirder than it has to be
 * because of the async sockets. Not using this code will cause notifications
 * to silently fail.
 */
static ssize_t
ptm_lldp_recv_cb (lldpctl_conn_t *conn,
                  const uint8_t *data,
                  size_t length,
                  void *user_data)
{
    int fd = PTM_MODULE_FD(ptm_lldp.gbl, LLDP_MODULE, 0);
    int each_len = 0;
    int rc;
    int retries = 0;

    while (each_len != length) {
        rc = recv(fd, (void *) (data + each_len), (length - each_len), 0);

        if (rc == 0) {
            ERRLOG("recv error(%s) - connection closed?\n", strerror(errno));
            return (-1);
        }

        if (rc < 0) {
            if (errno != EAGAIN) {
                ERRLOG("fatal recv error(%s), closing connection, rc %d\n",
                       strerror(errno), rc);
                return (-1);
            } else {
                if (retries++ < 5) {
                    usleep(2000);
                    continue;
                }
                DLOG("max retries - recv error(%d - %s) bytes read %d (%d)\n",
                     errno, strerror(errno), each_len, (int)length);
                return (each_len);
            }
        } else {
            each_len += rc;
        }
    }

    return (each_len);
}

#define UPDATE_FIELD(d, s) \
            if (event->s) strncpy(l_port->d, event->s, sizeof(l_port->d)); \
            else strncpy(l_port->d, "N/A", sizeof(l_port->d))

static void
copy_event_to_lport(ptm_event_t *event, lldp_port *l_port)
{
    UPDATE_FIELD(liface, liface);
    UPDATE_FIELD(port_name, riface);
    UPDATE_FIELD(port_descr, rdescr);
    UPDATE_FIELD(mac_addr, rmac);
    UPDATE_FIELD(ipv4_addr, rv4addr);
    UPDATE_FIELD(ipv6_addr, rv6addr);
    UPDATE_FIELD(sys_name, rname);
    time(&l_port->last_change_time);
}

static void
handle_lldp_event_add(ptm_event_t *event)
{
    ptm_status_ctxt_t p_ctxt = {0};
    lldp_parms_hash_t *entry = NULL;
    ptm_conf_port_t *port = NULL;
    lldp_port *l_port = NULL;
    bool existing = FALSE;
    char *port_ident_str;
    bool update = FALSE;
    lldp_match_type_t match_type;
    int match_hostname;

    INFOLOG("Recd LLDP ADD event for port %s remote [%s - %s]\n",
         event->liface, event->rname, event->riface);

    port = ptm_conf_get_port(event);
    if (!port) {
        DLOG("%s: Port %s not found \n", __FUNCTION__, event->liface);
        return;
    }

    HASH_FIND(ph, lldp_port_hash, port->port_name,
              strlen(port->port_name), l_port);

    if (l_port)
        existing = TRUE;

    /* see if any LLDP parms associated with this port */
    HASH_FIND(ph, lldp_parms_hash, port->port_name,
            strlen(port->port_name), entry);

    match_type =
        (entry)?entry->parms.match_type:ptm_lldp.parms.match_type;
    match_hostname =
        (entry)?entry->parms.match_hostname:ptm_lldp.parms.match_hostname;

    /* compare with ptm conf and see if topo action needs to be called */
    if (match_type == PORT_DESCRIPTION) {
        port_ident_str = event->rdescr;
    } else {
        port_ident_str = event->riface;
    }

    if (match_hostname == PTM_HOST_NAME_TYPE_HOSTNAME) {
        event->rname = ptm_conf_prune_hostname(event->rname);
    }

    if (!existing) {
        l_port = calloc(1, sizeof(*l_port));
        if (!l_port) {
            ERRLOG("Can't malloc memory for new LLDP port: %s\n",
               port->port_name);
            return;
        }
        copy_event_to_lport(event, l_port);
        HASH_ADD(ph, lldp_port_hash, liface,
                strlen(l_port->liface), l_port);
    }

    l_port->match_type = match_type;
    l_port->match_hostname = match_hostname;

    if (!strlen(port->nbr_sysname) ||
        !strlen(port->nbr_ident)) {
        /* if user never specified full nbr info in topo file
         * we should ignore LLDP checks
         * have seen one customer do this - when they dont
         * care for LLDP but only want BFD configured on a port
         */
        DLOG("Port %s Ignore LLDP event - nbr not fully defined\n",
             port->port_name);
        return;
    }

    if (port_ident_str &&
        (strcmp(port->nbr_ident, port_ident_str) == 0) &&
        (strcmp(port->nbr_sysname, event->rname) == 0)) {
        if (port->topo_oper_state != PTM_TOPO_STATE_PASS) {
            port->topo_oper_state = PTM_TOPO_STATE_PASS;
            INFOLOG("Port %s correctly matched with remote %s.%s\n",
                    port->port_name, event->rname, port_ident_str);
            p_ctxt.port = port;
            p_ctxt.set_env_var = 1;
            ptm_conf_topo_action(&p_ctxt, TRUE);
        }
        update = TRUE;
    } else if (port->topo_oper_state == PTM_TOPO_STATE_NO_INFO) {
        port->topo_oper_state = PTM_TOPO_STATE_FAIL;
        INFOLOG("Port %s NOT matched with remote - "
                "Expected [%s.%s] != [%s.%s]\n",
                port->port_name,
                port->nbr_sysname, port->nbr_ident,
                event->rname,
                port_ident_str?port_ident_str:"N/A");
        p_ctxt.port = port;
        p_ctxt.set_env_var = 1;
        ptm_conf_topo_action(&p_ctxt, FALSE);
        update = TRUE;
    }

    if (update) {
        copy_event_to_lport(event, l_port);
    }
}

static void
handle_lldp_event_update(ptm_event_t *event)
{
    ptm_status_ctxt_t p_ctxt = {0};
    ptm_conf_port_t *port = NULL;
    lldp_port *l_port = NULL;
    char *port_ident_str;
    bool update = FALSE;

    INFOLOG("Recd LLDP UPDATE event for port %s remote [%s - %s]\n",
         event->liface, event->rname, event->riface);

    port = ptm_conf_get_port(event);
    if (!port) {
        DLOG("%s: Port %s not found \n", __FUNCTION__, event->liface);
        return;
    }

    HASH_FIND(ph, lldp_port_hash, port->port_name,
              strlen(port->port_name), l_port);

    if (!l_port) {
        INFOLOG("Update event on non-existing LLDP port %s - Ignore\n",
                event->liface);
        return;
    }

    if (l_port->match_type == PORT_DESCRIPTION) {
        port_ident_str = event->rdescr;
    } else {
        port_ident_str = event->riface;
    }

    if (l_port->match_hostname == PTM_HOST_NAME_TYPE_HOSTNAME) {
        event->rname = ptm_conf_prune_hostname(event->rname);
    }

    if (!strlen(port->nbr_sysname) ||
        !strlen(port->nbr_ident)) {
        /* if user never specified full nbr info in topo file
         * we should ignore LLDP checks
         * have seen one customer do this - when they dont
         * care for LLDP but only want BFD configured on a port
         */
        DLOG("Port %s Ignore LLDP event - nbr not fully defined\n",
             port->port_name);
        return;
    }

    if (port_ident_str &&
        (strcmp(port->nbr_ident, port_ident_str) == 0) &&
        (strcmp(port->nbr_sysname, event->rname) == 0)) {
        if (port->topo_oper_state != PTM_TOPO_STATE_PASS) {
            port->topo_oper_state = PTM_TOPO_STATE_PASS;
            INFOLOG("Port %s correctly matched with remote %s.%s\n",
                    port->port_name, event->rname, port_ident_str);
            p_ctxt.port = port;
            ptm_conf_topo_action(&p_ctxt, TRUE);
        }
        update = TRUE;
    } else if (port->topo_oper_state == PTM_TOPO_STATE_PASS) {
        port->topo_oper_state = PTM_TOPO_STATE_FAIL;
        INFOLOG("Port %s NOT matched with remote - "
            "Expected [%s.%s] != [%s.%s]\n",
            port->port_name,
            port->nbr_sysname, port->nbr_ident,
            event->rname,
            (port_ident_str)?port_ident_str:"N/A");
        p_ctxt.port = port;
        ptm_conf_topo_action(&p_ctxt, FALSE);
        update = TRUE;
    }

    if (update) {
        copy_event_to_lport(event, l_port);
    }
}

static void
handle_lldp_event_del(ptm_event_t *event)
{
    ptm_status_ctxt_t p_ctxt = {0};
    ptm_conf_port_t *port = NULL;
    lldp_port *l_port = NULL;

    INFOLOG("Recd LLDP DEL event for port %s remote [%s - %s]\n",
         event->liface, event->rname, event->riface);

    HASH_FIND(ph, lldp_port_hash, event->liface,
              strlen(event->liface), l_port);

    if (!l_port) {
        DLOG("%s: LLDP nbr not found for port %s\n", __FUNCTION__,
             event->liface);
        return;
    }

    port = ptm_conf_get_port(event);
    if (!port) {
        DLOG("%s: Port %s not found \n", __FUNCTION__, event->liface);
        return;
    }

    if ((strcmp(l_port->port_name, event->riface) == 0) &&
        (strcmp(l_port->sys_name, event->rname) == 0)) {
        if (port->topo_oper_state != PTM_TOPO_STATE_FAIL) {
            port->topo_oper_state = PTM_TOPO_STATE_FAIL;
            INFOLOG("Port %s Removed by LLDP - remote %s.%s\n",
                    port->port_name, l_port->sys_name, event->riface);
            p_ctxt.port = port;
            ptm_conf_topo_action(&p_ctxt, FALSE);
        }
        port->topo_oper_state = PTM_TOPO_STATE_NO_INFO;
        HASH_DELETE(ph, lldp_port_hash, l_port);
        free(l_port);
    }
}

/**
 * Process events for lldp/cable checks
 */
static int
ptm_event_lldp(ptm_event_t *event)
{
    switch (event->type) {
    case EVENT_ADD:
        handle_lldp_event_add(event);
        break;
    case EVENT_UPD:
        handle_lldp_event_update(event);
        break;
    case EVENT_DEL:
        handle_lldp_event_del(event);
        break;
    default:
        DLOG("%s: Unknown event (%d) received for port %s\n", __FUNCTION__,
                event->type, event->liface);
    }

    return(0);
}

/**
 * Register with LLDPD over the LLDPCTL interface to watch for neighbor
 * events and get callbacks.
 */
static int
ptm_process_lldp (int in_fd,
                  ptm_sockevent_e se,
                  void *udata)
{
    char buffer[CTL_MSG_SZ];
    int rc, num_msg;

    if (PTM_GET_STATE(ptm_lldp.gbl) != PTM_RUNNING) {
        return (-1);
    }

    if (!ptm_lldp.conn) {
        return (-1);
    }

    switch (se) {
    case SOCKEVENT_READ:
        rc = ptm_lldp_recv_cb(ptm_lldp.conn, (const uint8_t *)buffer,
                              sizeof(buffer), NULL);
        if (rc < 0) {
            sprintf(ptm_lldp.err_str, "ptm_lldp recv failure (rc=%d)", rc);
            ptm_shutdown_lldp();
            return (-1);
        }

        if (rc == 0) {
            break;
        }

        /* This copies the data into the conn's internal buffer and processes
         * one message.
         */
        if (lldpctl_recv(ptm_lldp.conn, (const uint8_t *)buffer, rc) < 0) {
            sprintf(ptm_lldp.err_str,
                    "lldpctl_recv error - lldpctl[%s]",
                    lldpctl_last_strerror(ptm_lldp.conn));
            ptm_shutdown_lldp();
            return (-1);
        }

        /* process any additional data in buffer (upto 5) */
        num_msg = 0;
        do {
            rc = lldpctl_process_conn_buffer(ptm_lldp.conn);
            num_msg++;
        } while ((rc == 0) && (num_msg < 5));
        break;

    case SOCKEVENT_WRITE:
        if (lldpctl_send(ptm_lldp.conn) < 0) {
            sprintf(ptm_lldp.err_str,
                    "lldpctl_send error - lldpctl[%s]",
                    lldpctl_last_strerror(ptm_lldp.conn));
            ptm_shutdown_lldp();
            return (-1);
        }
        break;

    default:
        break;
    }
    return (0);
}

static void
ptm_lldp_free_non_existent_ports(void)
{
    int old;
    ptm_status_ctxt_t p_ctxt = {0};
    struct ptm_conf_port *port, tmp_port;
    lldp_port *l_port, *tmp;

    /* remove non-existing ports */
    old = HASH_CNT(ph, lldp_port_hash);
    HASH_ITER(ph, lldp_port_hash, l_port, tmp) {
        port = ptm_conf_get_port_by_name(l_port->liface);
        if (!port) {
            /* only inform clients */
            strcpy(tmp_port.port_name, l_port->liface);
            tmp_port.topo_oper_state = PTM_TOPO_STATE_FAIL;
            INFOLOG("LLDP Port %s not existing - topo-action\n",
                    tmp_port.port_name);
            p_ctxt.port = &tmp_port;
            ptm_conf_topo_action (&p_ctxt, FALSE);
            HASH_DELETE(ph, lldp_port_hash, l_port);
            free(l_port);
        }
    }

    if (old - HASH_CNT(ph, lldp_port_hash)) {
        INFOLOG("%s: Deleted non-existent ports %d\n", __FUNCTION__,
                old - HASH_CNT(ph, lldp_port_hash));
    }
}

static int
ptm_populate_lldp ()
{
    int ret;

    INFOLOG("%s: Post Init operations \n", __FUNCTION__);

    if (ptm_lldp.conn == NULL)
        return (-1);

    /* request a resync */
    ptm_lldp.resync = TRUE;

    ptm_lldp.in_cache_loop = 1;

    ret = ptm_lldp_sync_nbrs();

    ptm_lldp.in_cache_loop = 0;

    if (ret) {
        sprintf(ptm_lldp.err_str, "%s: LLDPCTL sync failed - retry",
            __FUNCTION__);
        ptm_shutdown_lldp();
        return ret;
    }

    /*
     * start watching for neighbor events.
     * We make sure a dummy parm is passed - to differentiate
     * between lldpctl notification and internal call
     * parm=1, lldpctl notification
     * parm=0, ptm internal call
     */
    ret = lldpctl_watch_callback(ptm_lldp.conn,
                process_lldp_neighbors_cb, (void *)1);

    if (ret) {
        sprintf(ptm_lldp.err_str,
                "lldpctl_watch_callback failed - lldpctl[%s]",
                lldpctl_last_strerror(ptm_lldp.conn));
        ptm_shutdown_lldp();
    } else {
        PTM_MODULE_SET_STATE(ptm_lldp.gbl, LLDP_MODULE, MOD_STATE_POPULATE);
    }

    return (0);
}

/**
 * Entry routine to the LLDP module of PTM. It creates an AF_UNIX socket
 * and connects to LLDPD.
 */
int
ptm_init_lldp (ptm_globals_t *g)
{
    int s, flags;
    int ret = 0;
    const char *name;
    struct sockaddr_un su;

    ptm_lldp.gbl = g;

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, LLDP_MODULE);
    PTM_MODULE_EVENTCB(g, LLDP_MODULE) = ptm_event_lldp;
    PTM_MODULE_POPULATECB(g, LLDP_MODULE) = ptm_populate_lldp;
    PTM_MODULE_PROCESSCB(g, LLDP_MODULE) = ptm_process_lldp;
    PTM_MODULE_PARSECB(g, LLDP_MODULE) = ptm_parse_lldp;
    PTM_MODULE_STATUSCB(g, LLDP_MODULE) = ptm_status_lldp;

    /* init global default */
    ptm_lldp.parms.match_type = PORTID_IFNAME;
    ptm_lldp.parms.match_hostname = PTM_HOST_NAME_TYPE_HOSTNAME;

    /* init lldpctl connectivity */
    name = lldpctl_get_default_transport();
    flags = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
    if ((s = socket(PF_UNIX, flags, 0)) == -1) {
        sprintf(ptm_lldp.err_str,
                "Create socket failed (%s)", strerror(errno));
        ptm_shutdown_lldp();
        return (-1);
    }

    PTM_MODULE_SET_FD(ptm_lldp.gbl, s, LLDP_MODULE, 0);

    su.sun_family = AF_UNIX;
    memset(su.sun_path, 0, sizeof(su.sun_path));
    strncpy(su.sun_path, name, sizeof(su.sun_path));
    if (connect(s, (struct sockaddr *)&su, sizeof(struct sockaddr_un)) == -1) {
        ptm_lldp.err_str[0] = '\0';
        if (ptm_lldp.mod_retry_cnt < MOD_LLDP_RETRY_COUNT) {
            sprintf(ptm_lldp.err_str,
                    "%s: socket connect failed (%s) retry [%d]",
                   __FUNCTION__, strerror(errno), ptm_lldp.mod_retry_cnt);
        }
        ptm_shutdown_lldp();
        return (-1);
    }

    /* create the client connection structure */
    ptm_lldp.conn = lldpctl_new(ptm_lldp_send_cb, ptm_lldp_recv_cb, NULL);
    if (ptm_lldp.conn == NULL) {
        sprintf(ptm_lldp.err_str, "Failed to get LLDPCTL connection");
        ptm_shutdown_lldp();
        return (-1);
    }

    INFOLOG("Successfully connected to LLDP socket\n");

    /*
     * get local system information from LLDPD. This creates the socket
     * and connects to LLDPD if necessary.
     */
    ret = get_local_params(ptm_lldp.conn);

    if (ret) {
        sprintf(ptm_lldp.err_str,
            "Failed to get local host info from LLDP");
        ptm_shutdown_lldp();
        return (-1);
    }

    ptm_lldp.mod_retry_cnt = 0;
    PTM_MODULE_SET_STATE(g, LLDP_MODULE, MOD_STATE_INITIALIZED);

    return (ret);
}

static int lldp_parse_match_type(lldp_parms_t *parms, char *val)
{
    int i = 0;
    while (type_list[i].str) {
        if (!strcasecmp(val, type_list[i].str)) {
            DLOG("%s: Found supported value [%s] \n", __FUNCTION__, val);
            parms->match_type = type_list[i].type;
            /* we are done */
            return 0;
        }
        i++;
    }
    DLOG("%s: Unsupported value [%s] \n", __FUNCTION__, val);
    return -1;
}

static int lldp_parse_match_hostname(lldp_parms_t *parms, char *val)
{
    int i = 0;
    while (hostname_list[i].str) {
        if (!strcasecmp(val, hostname_list[i].str)) {
            DLOG("%s: Found supported value [%s] \n", __FUNCTION__, val);
            parms->match_hostname = hostname_list[i].type;
            /* we are done */
            return 0;
        }
        i++;
    }
    DLOG("%s: Unsupported value [%s] \n", __FUNCTION__, val);
    return -1;
}

static void
ptm_parse_lldp_template(char *args, char *tmpl)
{
    char val[MAX_ARGLEN];
    tmpl[0] = '\0';
    ptm_conf_find_key_val(LLDP_TEMPLATE_KEY, args, val);
    if (strlen(val)) {
        DLOG("%s: Found template [%s] \n", __FUNCTION__, val);
        ptm_conf_get_template_str(val, tmpl);
    }
    return;
}

static int ptm_parse_lldp(struct ptm_conf_port *port, char *args)
{
    lldp_parms_hash_t *entry = NULL, *curr;
    char in_args[MAX_ARGLEN];
    char val[MAX_ARGLEN], tmpl_str[MAX_ARGLEN];
    int rval, i, change = 0;

    INFOLOG("lldp %s args %s\n", port->port_name,
            (args && strlen(args))?args:"None");

    HASH_FIND(ph, lldp_parms_hash, port->port_name,
              strlen(port->port_name), curr);

    if (curr) {
        HASH_DELETE(ph, lldp_parms_hash, curr);
        free(curr);
        curr = NULL;
    }

    if (!args)
        return -1;

    assert(strlen(args) <= MAX_ARGLEN);
    strcpy(in_args, args);

    /* check if there is a template defined  */
    ptm_parse_lldp_template(in_args, tmpl_str);

    if (strlen(tmpl_str)) {
        INFOLOG("%s: Allow template [%s]\n", __FUNCTION__, tmpl_str);
        strcpy(in_args, tmpl_str);
    }

    /* create a hash entry */
    entry = (lldp_parms_hash_t *)calloc(1, sizeof(*entry));
    if (!entry) {
        DLOG("%s: parm alloc failure \n", __FUNCTION__);
        return 0;
    }

    strncpy(entry->port_name, port->port_name,
            sizeof(entry->port_name));
    /* Initialize port defaults with global defaults */
    entry->parms.match_type = ptm_lldp.parms.match_type;
    entry->parms.match_hostname = ptm_lldp.parms.match_hostname;

    /* check for valid params */
    for(i = 0; lldp_parms_key[i].key; i++) {

        ptm_conf_find_key_val(lldp_parms_key[i].key, in_args, val);

        if (strlen(val)) {
            /* found key/val */
            rval = lldp_parms_key[i].key_cb(&entry->parms, val);
            if (!rval)
                change = 1;
        }
    }

    if (change) {
        if (curr) {
            HASH_DELETE(ph, lldp_parms_hash, curr);
            free(curr);
        }
        HASH_ADD(ph, lldp_parms_hash, port_name,
                 strlen(entry->port_name), entry);
    } else {
        free(entry);
    }

    return 0;
}

static void
ptm_lldp_time_str(char *tstr, time_t t)
{
    time_t now;
    double elapsed;
    int days, hrs, mins;
    char tmpbuf[32];

    if (!t) {
        strcpy(tstr, "Nyet");
        return;
    }

    time(&now);
    elapsed = difftime(now, t);

    tstr[0] = '\0';
    if (elapsed > (24*3600)) {
        days = elapsed/(24*3600);
        elapsed -= (days*24*3600);
        sprintf(tmpbuf, "%dd:", days);
        strcat(tstr, tmpbuf);
    }
    if (elapsed > 3600) {
        hrs = elapsed/3600;
        elapsed -= (hrs*3600);
        sprintf(tmpbuf, "%dh:", hrs);
        strcat(tstr, tmpbuf);
    }
    if (elapsed > 60) {
        mins = elapsed/60;
        sprintf(tmpbuf, "%2dm:", mins);
        strcat(tstr, tmpbuf);
        elapsed -= (mins*60);
    }

    sprintf(tmpbuf, "%2ds", (int)elapsed);
    strcat(tstr, tmpbuf);
}

#define UPDATE_ENV_VAR(s, v) {  \
            if (strlen(v)) setenv(s, v, 1); \
            else setenv(s, "N/A", 1); \
        }

static int
ptm_status_lldp(void *m_ctxt, void *in_ctxt, void *out_ctxt)
{
    char val[MAXNAMELEN+1], modstr[MAXNAMELEN+1];
    ptm_status_ctxt_t *p_ctxt;
    struct ptm_conf_port *port = NULL;
    lldp_port *l_port = NULL;
    char liface[MAXNAMELEN+1];
    char oper_state[MAXNAMELEN+1];
    char abuf[2*(MAXNAMELEN+1)];
    char ebuf[2*(MAXNAMELEN+1)];
    char tbuf[32];
    char matchon[32];
    char sysname[MAXNAMELEN+1];
    char portname[MAXNAMELEN+1];
    char portdescr[MAXNAMELEN+1];
    char *port_ident_str = NULL;
    int detail = FALSE;
    int set_env = FALSE;

    /* figure out the params */
    if (!ptm_lib_find_key_in_msg(in_ctxt, "module", modstr)) {
        if (!strcasecmp(modstr, ptm_module_string(LLDP_MODULE))) {
            l_port = m_ctxt;
            port = ptm_conf_get_port_by_name(l_port->liface);
        } else if (!strcasecmp(modstr, ptm_module_string(CONF_MODULE))) {
            p_ctxt = m_ctxt;
            port = p_ctxt->port;
            set_env = p_ctxt->set_env_var;
            HASH_FIND(ph, lldp_port_hash, port->port_name,
                  strlen(port->port_name), l_port);
        } else {
            /* not the relevant module */
            return PTM_CMD_OK;
        }
    } else {
        /* no module specified - assume default */
        p_ctxt = m_ctxt;
        port = p_ctxt->port;
        set_env = p_ctxt->set_env_var;
        HASH_FIND(ph, lldp_port_hash, port->port_name,
                  strlen(port->port_name), l_port);
    }

    if (!ptm_lib_find_key_in_msg(in_ctxt, "detail", val) &&
        !strcasecmp(val, "yes"))
        detail = TRUE;

    /* initialize the defaults */
    strcpy(liface, "N/A");
    sprintf(oper_state, "N/A");
    if (l_port) {
        if (l_port->match_type == PORT_DESCRIPTION)
            port_ident_str = l_port->port_descr;
        else
            port_ident_str = l_port->port_name;
        strcpy(liface, l_port->liface);
        if (port) {
            if (port->topo_oper_state == PTM_TOPO_STATE_PASS)
                sprintf(oper_state, "pass");
            else if (port->topo_oper_state == PTM_TOPO_STATE_FAIL)
                sprintf(oper_state, "fail");
        }
    } else if (port) {
        strcpy(liface, port->port_name);
    }

    sprintf(ebuf, "no-info:no-info");
    sprintf(matchon, "N/A");
    sprintf(sysname, "N/A");
    sprintf(portname, "N/A");
    sprintf(portdescr, "N/A");
    sprintf(abuf, "no-info");
    sprintf(tbuf, "N/A");
    if (port)
        sprintf(ebuf, "%s:%s", port->nbr_sysname, port->nbr_ident);
    if (l_port) {
        ptm_lldp_time_str(tbuf, l_port->last_change_time);
        if (port && (port->topo_oper_state != PTM_TOPO_STATE_NO_INFO))
            sprintf(abuf, "%s:%s", l_port->sys_name, port_ident_str);
        if (l_port->match_type == PORT_DESCRIPTION) {
            sprintf(matchon, "PortDescr");
        } else {
            sprintf(matchon, "IfName");
        }
        sprintf(sysname, "%s", l_port->sys_name);
        sprintf(portname, "%s", l_port->port_name);
        sprintf(portdescr, "%s", l_port->port_descr);
    }

    /* start adding data */
    ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt, "port", liface);
    ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt, "cbl status",
                       oper_state);
    if (detail) {
        ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt,
                           "exp nbr", ebuf);
        ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt,
                           "act nbr", abuf);
        ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt,
                           "sysname", sysname);
        ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt,
                           "portID", portname);
        ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt,
                           "portDescr", portdescr);
        ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt,
                           "match on", matchon);
        ptm_lib_append_msg(ptm_lldp.gbl->ptmlib_hdl, out_ctxt,
                           "last upd", tbuf);
    }

    if (set_env) {
        UPDATE_ENV_VAR(PTM_ENV_VAR_PORT, liface);
        UPDATE_ENV_VAR(PTM_ENV_VAR_CBLSTATUS, oper_state);
        UPDATE_ENV_VAR(PTM_ENV_VAR_EXPNBR, ebuf);
        UPDATE_ENV_VAR(PTM_ENV_VAR_ACTNBR, abuf);
    }

    return (PTM_CMD_OK);
}

void *ptm_lldp_get_next_sess_iter(void *ptr)
{
    lldp_port *l_port = ptr;

    return ((!l_port)?lldp_port_hash:l_port->ph.next);
}

#ifdef LLDPCTL_DEBUG
void ptm_lldpctl_log(int severity, const char *msg)
{
    INFOLOG("lldpctl: %s\n", msg);
}
#endif
