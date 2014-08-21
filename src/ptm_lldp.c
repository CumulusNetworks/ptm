/*********************************************************************
 * Copyright 2013 Cumulus Networks, Inc.  All rights reserved.
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
#include "ptm_lldp.h"
#include "ptm_ctl.h"
#include "lldpctl.h"
#include "log.h"

static int lldp_parse_match_type(lldp_parms_t *parms, char *val);
static int ptm_populate_lldp ();
static int ptm_process_lldp (int in_fd, ptm_sockevent_e se, void *udata);
static int ptm_parse_lldp(struct ptm_conf_port *port, char *args);
static int ptm_status_lldp(csv_t *, csv_record_t **, csv_record_t **,
                           char *, void *);
static int ptm_debug_lldp(csv_t *, csv_record_t **, csv_record_t **,
                          char *, void *, char *);
static void ptm_start_lldp_resync_timer(void);
static void ptm_stop_lldp_resync_timer(void);
static int ptm_lldp_resync_nbrs(void);

/* This needs the latest LLDPd from https://github.com/vincentbernat/lldpd */
extern int lldpctl_process_conn_buffer(lldpctl_conn_t *conn);

lldp_parms_hash_t *lldp_parms_hash = NULL;

lldp_parms_key_t lldp_parms_key[] = {
        { .key = "match_type", .key_cb = lldp_parse_match_type },
        { .key = NULL, .key_cb = NULL},
};

match_type_list type_list[] = {
        { .str = "portdescr", .type = PORT_DESCRIPTION},
        { .str = "ifname", .type = PORTID_IFNAME},
        { .str = NULL },
};

char *LLDP_TEMPLATE_KEY = "lldptmpl";

/**
 * Do a periodic lazy sync - incase we missed any events
 */
#define LLDPD_PERIODIC_RESYNC_INTERVAL  300

#define MOD_RETRY_DISPLAY_INTERVAL  5

/**
 * Global structure (private to this file) for bookkeeping - init params,
 * input params, statistics, and such.
 */
typedef struct {
    lldpctl_conn_t  *conn;
    ptm_globals_t   *gbl;
    ptm_event_t     event;
    uint64_t        num_notifs;
    uint64_t        num_lldp_restarts;
    lldp_parms_t    parms;
    cl_timer_t      *resync_timer;
    unsigned int    mod_retry_cnt;
} ptm_lldp_globals_t;

ptm_lldp_globals_t ptm_lldp;

lldp_port *lldp_port_hash = NULL;

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
    event->liface = strdup(lldpctl_atom_get_str(interface,
                                             lldpctl_k_interface_name));
    event->riface = strdup(lldpctl_atom_get_str(neighbor,
                                             lldpctl_k_port_id));
    event->rdescr = strdup(lldpctl_atom_get_str(neighbor,
                                             lldpctl_k_port_descr));
    event->rname = strdup(lldpctl_atom_get_str(neighbor,
                                             lldpctl_k_chassis_name));
    event->rmac = strdup(lldpctl_atom_get_str(neighbor,
                                             lldpctl_k_port_id));
    mgmts = mgmt = NULL;
    mgmts = lldpctl_atom_get(neighbor, lldpctl_k_chassis_mgmt);
    lldpctl_atom_foreach(mgmts, mgmt) {
        event->rmgmtip = strdup(lldpctl_atom_get_str(mgmt, lldpctl_k_mgmt_ip));
        break;
    }

    if (mgmt)
        lldpctl_atom_dec_ref(mgmt);
    if (mgmts)
        lldpctl_atom_dec_ref(mgmts);

    return (0);
}

/**
 * Callback passed to LLDPCTL as part of watch registration.
 *   Gets called when LLDPD sends a notification to the client about some
 *   change.
 */
static void
watch_lldp_neighbors_cb (lldpctl_conn_t *conn,
                         lldpctl_change_t type,
                         lldpctl_atom_t *interface,
                         lldpctl_atom_t *neighbor,
                         void *data)
{

    ptm_lldp.num_notifs++;

    if (!_extract_event(&ptm_lldp.event, lldp_type_to_ptm_event_type(type),
                         interface, neighbor)) {
        if (ptm_lldp.event.liface &&
            (ptm_lldp.event.riface || ptm_lldp.event.rdescr))
            ptm_module_handle_event_cb(&ptm_lldp.event);
        else
            ERRLOG("%s: local iface and remote iface/descr not set\n",
                __FUNCTION__);
    }
    ptm_event_cleanup(&ptm_lldp.event);
}

/**
 * Get a dump of local interfaces and neighbors from LLDPD. Typically called
 * at initialization time.
 */
static int
get_lldp_neighbor_list (lldpctl_conn_t *conn)
{
    lldpctl_atom_t *iface_list = NULL;
    lldpctl_atom_t *iface = NULL;
    lldpctl_atom_t *port = NULL;
    lldpctl_atom_t *neighbors = NULL;
    lldpctl_atom_t *neighbor = NULL;
    lldpctl_atom_iter_t *iter = NULL;

    if (!conn) {
        return (-1);
    }
    iface_list = lldpctl_get_interfaces(conn);
    if (!iface_list) {
        ERRLOG("initial pull from LLDP failed (%s)\n",
               lldpctl_last_strerror(conn));
        return (-1);
    }

    iter = lldpctl_atom_iter(iface_list);
    while (iter != NULL) {
        iface = lldpctl_atom_iter_value(iface_list, iter);
        port = lldpctl_get_port(iface);
        neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);
        lldpctl_atom_foreach(neighbors, neighbor) {
            watch_lldp_neighbors_cb(conn, lldpctl_c_added, iface, neighbor,
                                    NULL);
        }
        if (neighbors)
            lldpctl_atom_dec_ref(neighbors);
        if (port)
            lldpctl_atom_dec_ref(port);

        lldpctl_atom_dec_ref(iface);
        iter = lldpctl_atom_iter_next(iface_list, iter);
    }
    lldpctl_atom_dec_ref(iface_list);

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
    int found = 0;

    iface_list = lldpctl_get_interfaces(conn);
    if (!iface_list) {
        ERRLOG("%s : lldpctl_get_interfaces from LLDP failed (%s)\n",
               __FUNCTION__, lldpctl_last_strerror(conn));
        return (-1);
    }

    iter = lldpctl_atom_iter(iface_list);
    while (iter != NULL) {
        iface = lldpctl_atom_iter_value(iface_list, iter);
        port = lldpctl_get_port(iface);
        if (port == NULL) {
            ERRLOG("%s: lldp error - can't find port for iface\n",
                   __FUNCTION__);
            lldpctl_atom_dec_ref(iface);
            continue;
        }
        if (!found) {
            ptm_lldp.gbl->my_hostname =
                strdup(lldpctl_atom_get_str(port, lldpctl_k_chassis_name));
            if (strlen(ptm_lldp.gbl->my_hostname))
                found = 1;

            mgmts = lldpctl_atom_get(port, lldpctl_k_chassis_mgmt);
            lldpctl_atom_foreach(mgmts, mgmt) {
                ptm_lldp.gbl->my_mgmtip =
                    strdup(lldpctl_atom_get_str(mgmt, lldpctl_k_mgmt_ip));
                if (strlen(ptm_lldp.gbl->my_mgmtip)) {
                    found = 1;
                    break;
                }
            }
            if (mgmt)
                lldpctl_atom_dec_ref(mgmt);
            if (mgmts)
                lldpctl_atom_dec_ref(mgmts);
        }
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

    if (ptm_lldp.conn) {
        lldpctl_release(ptm_lldp.conn);
        ptm_lldp.conn = NULL;
    }

    /* If select set readfd which then returned 0, ensure we remove
     *  this fd from the select list, or we get into an infinite loop
     *  with select waking us up again and again.
     */
    ptm_fd_cleanup(PTM_MODULE_FD(ptm_lldp.gbl, LLDP_MODULE));
    PTM_MODULE_SET_FD(ptm_lldp.gbl, -1, LLDP_MODULE);

    HASH_ITER(ph, lldp_port_hash, l_port, tmp) {
        HASH_DELETE(ph, lldp_port_hash, l_port);
        free(l_port);
    }

    ptm_stop_lldp_resync_timer();

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
    int fd = PTM_MODULE_FD(ptm_lldp.gbl, LLDP_MODULE);
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
                usleep(100);
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
    int fd = PTM_MODULE_FD(ptm_lldp.gbl, LLDP_MODULE);
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
                    usleep(100);
                    continue;
                }
                return (each_len);
            }
        } else {
            each_len += rc;
        }
    }
    return (each_len);
}

#define UPDATE_FIELD(d, s) \
            if (event->s) strncpy(l_port->d, event->s, sizeof(l_port->d))

static void
handle_lldp_event_add_update(ptm_event_t *event)
{
    lldp_parms_hash_t *entry = NULL;
    ptm_conf_port_t *port = NULL;
    struct ptm_conf_nbr *nbr;
    lldp_port *l_port = NULL;
    bool existing = FALSE;
    char *port_ident_str;

    DLOG("LLDP Received %s event for port %s\n",
         (event->type == EVENT_ADD)?"ADD":"UPD", event->liface);

    port = ptm_conf_get_port(event);
    if (!port) {
        DLOG("%s: Port %s not found \n", __FUNCTION__, event->liface);
        return;
    }

    nbr = &port->admin;

    HASH_FIND(ph, lldp_port_hash, port->port_name,
              strlen(port->port_name), l_port);

    if (l_port)
        existing = TRUE;

    if (event->type == EVENT_ADD) {
        /* allocate a new lldp port struct */
        if (!existing) {
            if ((l_port = calloc(1, sizeof(*l_port))) == NULL) {
                ERRLOG("Can't malloc memory for new LLDP port: %s\n",
                        nbr->port_ident);
                return;
            }
        }
    } else if (!existing) {
        DLOG("%s: LLDP Port %s not found \n", __FUNCTION__, event->liface);
        return;
    }

    UPDATE_FIELD(liface, liface);
    UPDATE_FIELD(sys_name, rname);
    UPDATE_FIELD(port_name, riface);
    UPDATE_FIELD(port_descr, rdescr);
    UPDATE_FIELD(mac_addr, rmac);
    UPDATE_FIELD(ipv4_addr, rv4addr);
    UPDATE_FIELD(ipv6_addr, rv6addr);

    /* see if any LLDP parms associated with this port */
    HASH_FIND(ph, lldp_parms_hash, port->port_name,
            strlen(port->port_name), entry);

    l_port->match_type =
        (entry)?entry->parms.match_type:ptm_lldp.parms.match_type;

    if (event->type == EVENT_ADD) {
        if (!existing) {
            HASH_ADD(ph, lldp_port_hash, liface,
                    strlen(l_port->liface), l_port);
        }
    }

    if (!existing)
        time(&l_port->last_change_time);

    /* compare with ptm conf and see if topo action needs to be called */
    if (l_port->match_type == PORT_DESCRIPTION) {
        port_ident_str = l_port->port_descr;
    } else {
        port_ident_str = l_port->port_name;
    }

    if ((strcmp(nbr->port_ident, port_ident_str) == 0) &&
        (strcmp(nbr->sys_name, l_port->sys_name) == 0)) {
        if (port->topo_oper_state != PTM_TOPO_STATE_PASS) {
            port->topo_oper_state = PTM_TOPO_STATE_PASS;
            INFOLOG("Port %s correctly matched with remote %s.%s\n",
                    port->port_name, l_port->sys_name, port_ident_str);
            ptm_conf_topo_action(port, TRUE);
        }
    } else if (port->topo_oper_state != PTM_TOPO_STATE_FAIL) {
        port->topo_oper_state = PTM_TOPO_STATE_FAIL;
        INFOLOG("Port %s NOT matched with remote - "
                "Expected [%s.%s] != [%s.%s]\n",
                port->port_name,
                nbr->sys_name, nbr->port_ident,
                l_port->sys_name, port_ident_str);
        ptm_conf_topo_action(port, FALSE);
    }
}

static void
handle_lldp_event_del(ptm_event_t *event)
{
    ptm_conf_port_t *port = NULL;
    lldp_port *l_port = NULL;

    DLOG("LLDP Received DEL event for port %s\n", event->liface);

    port = ptm_conf_get_port(event);
    if (!port) {
        DLOG("%s: Port %s not found \n", __FUNCTION__, event->liface);
        return;
    }

    HASH_FIND(ph, lldp_port_hash, port->port_name,
              strlen(port->port_name), l_port);

    if (!l_port) {
        DLOG("%s: LLDP nbr not found for port %s\n", __FUNCTION__,
             event->liface);
        return;
    }

    if (port->topo_oper_state != PTM_TOPO_STATE_FAIL) {
        port->topo_oper_state = PTM_TOPO_STATE_FAIL;
        ptm_conf_topo_action(port, FALSE);
    }
    port->topo_oper_state = PTM_TOPO_STATE_NO_INFO;
    HASH_DELETE(ph, lldp_port_hash, l_port);
    free(l_port);
}

/**
 * Process events for lldp/cable checks
 */
static int
ptm_event_lldp(ptm_event_t *event)
{
    switch (event->type) {
    case EVENT_ADD:
    case EVENT_UPD:
        handle_lldp_event_add_update(event);
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
    char buffer[512];
    int rc;

    if ((PTM_GET_STATE(ptm_lldp.gbl) == PTM_SHUTDOWN) ||
        (PTM_GET_STATE(ptm_lldp.gbl) == PTM_RECONFIG)) {
        return (-1);
    }

    if (!ptm_lldp.conn) {
        return (-1);
    }

    switch (se) {
    case SOCKEVENT_READ:
        rc = ptm_lldp_recv_cb(ptm_lldp.conn, (const uint8_t *)buffer, 512, NULL);
        if (rc <= 0) {
            ptm_shutdown_lldp();
            return (-1);
        }

        /* This copies the data into the conn's internal buffer and processes
         * one message.
         */
        if (lldpctl_recv(ptm_lldp.conn, (const uint8_t *)buffer, rc) < 0) {
            ERRLOG("rcv error (%s)\n", lldpctl_last_strerror(ptm_lldp.conn));
            ptm_shutdown_lldp();
            return (-1);
        }

        /* process any additional data in buffer */
        do {
            rc = lldpctl_process_conn_buffer(ptm_lldp.conn);
        } while (rc == 0);
        break;

    case SOCKEVENT_WRITE:
        if (lldpctl_send(ptm_lldp.conn) < 0) {
            ERRLOG("send error (%s)\n", lldpctl_last_strerror(ptm_lldp.conn));
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
ptm_lldp_resync_timer(cl_timer_t *timer,
                      void *context)
{
    int ret;

    DLOG("%s: Begin Resync LLDP nbrs Cnt = %d\n", __FUNCTION__,
         HASH_CNT(ph, lldp_port_hash));

    ret = ptm_lldp_resync_nbrs();

    if (ret) {
        ERRLOG("%s: LLDPCTL resync failed - retry\n", __FUNCTION__);
        ptm_shutdown_lldp();
    }

    DLOG("%s: End Resync LLDP nbrs Cnt = %d\n", __FUNCTION__,
         HASH_CNT(ph, lldp_port_hash));

    return;
}

static void ptm_stop_lldp_resync_timer(void)
{
    if (ptm_lldp.resync_timer) {
        cl_timer_destroy(ptm_lldp.resync_timer);
        ptm_lldp.resync_timer = NULL;
    }
}

static void
ptm_start_lldp_resync_timer(void)
{
    if (!ptm_lldp.resync_timer) {
        ptm_lldp.resync_timer = cl_timer_create();
        cl_timer_arm(ptm_lldp.resync_timer, ptm_lldp_resync_timer,
                     LLDPD_PERIODIC_RESYNC_INTERVAL, T_UF_PERIOIDIC);
    }
}

static int ptm_lldp_resync_nbrs(void)
{
    struct ptm_conf_port *port, tmp_port;
    lldp_port *l_port, *tmp;
    int ret, old;

    ret = get_lldp_neighbor_list(ptm_lldp.conn);

    if (ret) {
        return ret;
    }

    /* remove non-existing ports */
    old = HASH_CNT(ph, lldp_port_hash);
    HASH_ITER(ph, lldp_port_hash, l_port, tmp) {
        port = ptm_conf_get_port_by_name(l_port->liface);
        if (!port) {
            /* only inform clients */
            strcpy(tmp_port.port_name, l_port->liface);
            tmp_port.topo_oper_state = PTM_TOPO_STATE_FAIL;
            ptm_conf_topo_action (&tmp_port, FALSE);
            HASH_DELETE(ph, lldp_port_hash, l_port);
            free(l_port);
        }
    }

    if (old - HASH_CNT(ph, lldp_port_hash)) {
        DLOG("%s: Deleted non-existent ports %d\n", __FUNCTION__,
             old - HASH_CNT(ph, lldp_port_hash));
    }

    return ret;
}

static int
ptm_populate_lldp ()
{
    int ret;

    INFOLOG("%s: Post Init operations \n", __FUNCTION__);

    if (ptm_lldp.conn == NULL)
        return (-1);

    ptm_start_lldp_resync_timer();

    ret = ptm_lldp_resync_nbrs();

    if (ret) {
        ERRLOG("%s: LLDPCTL resync failed \n", __FUNCTION__);
        ptm_shutdown_lldp();
        return ret;
    }

    /*
     * start watching for neighbor events.
     */
    ret = lldpctl_watch_callback(ptm_lldp.conn, watch_lldp_neighbors_cb, NULL);

    if (ret) {
        ERRLOG("%s: LLDPCTL callback registration failed (%s)\n",
               __FUNCTION__, lldpctl_last_strerror(ptm_lldp.conn));
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
    char old_hostname[HOST_NAME_MAX+1] = {0};
    char old_mgmtip[INET6_ADDRSTRLEN+1] = {0};

    ptm_lldp.gbl = g;

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, LLDP_MODULE);
    PTM_MODULE_EVENTCB(g, LLDP_MODULE) = ptm_event_lldp;
    PTM_MODULE_POPULATECB(g, LLDP_MODULE) = ptm_populate_lldp;
    PTM_MODULE_PROCESSCB(g, LLDP_MODULE) = ptm_process_lldp;
    PTM_MODULE_PARSECB(g, LLDP_MODULE) = ptm_parse_lldp;
    PTM_MODULE_STATUSCB(g, LLDP_MODULE) = ptm_status_lldp;
    PTM_MODULE_DEBUGCB(g, LLDP_MODULE) = ptm_debug_lldp;

    /* init global default */
    ptm_lldp.parms.match_type = PORTID_IFNAME;

    /* init lldpctl connectivity */
    name = lldpctl_get_default_transport();
    flags = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
    if ((s = socket(PF_UNIX, flags, 0)) == -1) {
        ERRLOG("Create socket failed (%s)\n", strerror(errno));
        ptm_shutdown_lldp();
        return (-1);
    }

    PTM_MODULE_SET_FD(ptm_lldp.gbl, s, LLDP_MODULE);

    su.sun_family = AF_UNIX;
    memset(su.sun_path, 0, sizeof(su.sun_path));
    strncpy(su.sun_path, name, sizeof(su.sun_path));
    if (connect(s, (struct sockaddr *)&su, sizeof(struct sockaddr_un)) == -1) {
        if ((ptm_lldp.mod_retry_cnt < MOD_RETRY_DISPLAY_INTERVAL) ||
            (ptm_lldp.mod_retry_cnt % MOD_RETRY_DISPLAY_INTERVAL)) {
            ERRLOG("%s: socket connect failed (%s) retry [%d]\n",
                   __FUNCTION__, strerror(errno), ptm_lldp.mod_retry_cnt);
        }
        ptm_shutdown_lldp();
        return (-1);
    }

    /* create the client connection structure */
    ptm_lldp.conn = lldpctl_new(ptm_lldp_send_cb, ptm_lldp_recv_cb, NULL);
    if (ptm_lldp.conn == NULL) {
        ERRLOG("Failed to get LLDPCTL connection\n");
        ptm_shutdown_lldp();
        return (-1);
    }

    /*
     * get local system information from LLDPD. This creates the socket
     * and connects to LLDPD if necessary.
     */
    if (ptm_lldp.gbl->my_hostname)
        snprintf(old_mgmtip, HOST_NAME_MAX+1, "%s", ptm_lldp.gbl->my_hostname);

    if (ptm_lldp.gbl->my_mgmtip)
        snprintf(old_mgmtip, INET6_ADDRSTRLEN+1, "%s", ptm_lldp.gbl->my_mgmtip);

    ret = get_local_params(ptm_lldp.conn);

    if (ret) {
        ERRLOG("Failed to get LLDPCTL connection\n");
        ptm_shutdown_lldp();
        return (-1);
    }

    if (ptm_lldp.gbl->my_hostname) {
        if (strcmp(old_hostname, ptm_lldp.gbl->my_hostname))
            ptm_lldp.gbl->hostname_changed = true;
    } else if (strlen(old_hostname)) {
        ptm_lldp.gbl->hostname_changed = true;
    }

    if (ptm_lldp.gbl->my_mgmtip) {
        if (strcmp(old_mgmtip, ptm_lldp.gbl->my_mgmtip))
            ptm_lldp.gbl->mgmt_ip_changed = true;
    } else if (strlen(old_mgmtip)) {
        ptm_lldp.gbl->mgmt_ip_changed = true;
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

    DLOG("lldp %s args %s\n", port->port_name,
         (args && strlen(args))?args:"None");

    HASH_FIND(ph, lldp_parms_hash, port->port_name,
              strlen(port->port_name), curr);

    if (!args || !strlen(args)) {
        /* no args supplied - delete port param */
        if (curr) {
            HASH_DELETE(ph, lldp_parms_hash, curr);
            free(curr);
        }
        return 0;
    }

    assert(strlen(args) <= MAX_ARGLEN);
    strcpy(in_args, args);

    /* check if there is a template defined  */
    ptm_parse_lldp_template(in_args, tmpl_str);

    if (strlen(tmpl_str)) {
        DLOG("%s: Allow template [%s]\n", __FUNCTION__, tmpl_str);
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

static int
ptm_status_lldp(csv_t *csv, csv_record_t **hrec, csv_record_t **drec,
                char *opt, void *arg)
{
    struct ptm_conf_port *port = arg;
    struct ptm_conf_nbr *nbr = &port->admin;
    lldp_port *l_port = NULL;
    char abuf[2*(MAXNAMELEN+1)];
    char ebuf[2*(MAXNAMELEN+1)];
    char tbuf[32];
    char matchon[32];
    char sysname[MAXNAMELEN+1];
    char portname[MAXNAMELEN+1];
    char portdescr[MAXNAMELEN+1];
    char *port_ident_str = NULL;
    int detail = FALSE;
    char *dtlstr;

    /* get status cmd has only one option at this point */
    dtlstr = strtok_r(NULL, " ", &opt);

    if(dtlstr && !strcmp(dtlstr, "detail"))
        detail = TRUE;

    HASH_FIND(ph, lldp_port_hash, port->port_name,
              strlen(port->port_name), l_port);

    if (l_port) {
        if (l_port->match_type == PORT_DESCRIPTION)
            port_ident_str = l_port->port_descr;
        else
            port_ident_str = l_port->port_name;
    }

    /* first the header */
    if (detail)
        *hrec = csv_encode(csv, 9, "port", "cbl status", "exp nbr",
                "act nbr", "sysname", "portID", "portDescr",
                "match on", "last upd");
    else
        *hrec = csv_encode(csv, 2, "port", "cbl status");

    if (!*hrec) {
        ERRLOG("%s: Could not allocate csv hdr record\n", __FUNCTION__);
        return (PTM_CMD_ERROR);
    }

    if (detail) {
        sprintf(ebuf, "%s:%s", nbr->sys_name, nbr->port_ident);
        ptm_lldp_time_str(tbuf, (l_port)?l_port->last_change_time:0);

        sprintf(matchon, "N/A");
        sprintf(sysname, "N/A");
        sprintf(portname, "N/A");
        sprintf(portdescr, "N/A");
        sprintf(abuf, "no-info");
        if (l_port) {
            if (port->topo_oper_state != PTM_TOPO_STATE_NO_INFO)
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
    }

    /* now the data */
    if (detail)
        *drec = csv_encode(csv, 9, port->port_name,
                ((port->topo_oper_state == PTM_TOPO_STATE_PASS)?
                 "pass" : "fail"),
                ebuf, abuf, sysname, portname, portdescr, matchon, tbuf);
    else
        *drec = csv_encode(csv, 2, port->port_name,
                ((port->topo_oper_state == PTM_TOPO_STATE_PASS)?
                 "pass" : "fail"));

    if (!*drec) {
        ERRLOG("%s: Could not allocate csv data record\n", __FUNCTION__);
        return (PTM_CMD_ERROR);
    }

    return (PTM_CMD_OK);
}

static int
ptm_debug_lldp(csv_t *csv, csv_record_t **hr, csv_record_t **dr,
               char *opt, void *arg, char *err_str)
{
    lldp_port *l_port, *tmp;
    csv_record_t *hrec, *drec;
    char tbuf[32];
    char tmpbuf[32];

    if (!HASH_CNT(ph, lldp_port_hash)) {
        if (err_str)
            sprintf(err_str,
                    "No LLDP ports detected. Check connections");

        ERRLOG("%s: No LLDP ports detected. Check connections\n",
               __FUNCTION__);
        return (PTM_CMD_ERROR);
    }

    if (err_str)
        sprintf(err_str, "LLDP internal error");

    /* first the header */
    hrec = csv_encode(csv, 6, "port", "sysname", "portID",
                      "port descr","match on", "last upd");

    if (!hrec) {
        ERRLOG("%s: Could not allocate csv hdr record\n", __FUNCTION__);
        return (PTM_CMD_ERROR);
    }

    HASH_ITER(ph, lldp_port_hash, l_port, tmp) {

        ptm_lldp_time_str(tbuf, l_port->last_change_time);

        if (l_port->match_type == PORT_DESCRIPTION) {
            sprintf(tmpbuf, "PortDescr");
        } else {
            sprintf(tmpbuf, "IfName");
        }

        /* now the data */
        drec = csv_encode(csv, 6, l_port->liface, l_port->sys_name,
                          l_port->port_name, l_port->port_descr, tmpbuf, tbuf);
        if (!drec) {
            ERRLOG("%s: Could not allocate csv data record\n", __FUNCTION__);
            return (PTM_CMD_ERROR);
        }

    }

    return (PTM_CMD_OK);
}
