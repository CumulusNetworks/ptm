/*********************************************************************
 * Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
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
#include "ptm_event.h"
#include "ptm_timer.h"
#include "ptm_lldp.h"
#include "ptm_conf.h"
#include "lldpctl.h"
#include "log.h"

/**
 * How long do we wait before reconnecting to LLDPD if it restarts? in secs
 */
#define LLDPD_RECONNECT_INIT_DELAY      5
#define LLDPD_CONNECT_RETRY_INTERVAL    5
#define LLDPD_FETCH_DELAY_AFTER_CONNECT 5

/**
 * Global structure (private to this file) for bookkeeping - init params,
 * input params, statistics, and such.
 */
typedef struct {
    lldpctl_conn_t *conn;
    ptm_globals_t  *gbl;
    ptm_event_t    event;
    uint64_t       num_notifs;
    uint64_t       num_lldp_restarts;
    cl_timer_t     *connect_timer;
    cl_timer_t     *fetch_timer;
} ptm_lldp_globals_t;

ptm_lldp_globals_t ptm_lldp;

static void ptm_reinit_lldp(void);

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
 */
static int
_extract_event (ptm_event_t *event,
                ptm_event_e type,
                lldpctl_atom_t *interface,
                lldpctl_atom_t *neighbor)
{
    lldpctl_atom_t *mgmts, *mgmt;

    if (!event || !interface || !neighbor || (type >= EVENT_UNKNOWN)) {
        ERRLOG("%s: Unknown event/if/nbr/type\n", __FUNCTION__);
        return (-1);
    }
    event->type = type;
    event->module = LLDP_MODULE;
    event->liface = strdup(lldpctl_atom_get_str(interface,
                                             lldpctl_k_interface_name));
    event->riface = strdup(lldpctl_atom_get_str(neighbor,
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

    LOG("watch callback called(type %d)\n", (int)type);

    ptm_lldp.num_notifs++;

    _extract_event(&ptm_lldp.event, lldp_type_to_ptm_event_type(type),
                         interface, neighbor);
    if (ptm_lldp.event.liface && ptm_lldp.event.riface) {
        PTM_MODULE_EVENTCB(ptm_lldp.gbl, LLDP_MODULE)(&ptm_lldp.event);
    } else {
        LOG("%s: local iface and remote iface not set\n", __FUNCTION__);
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
        ERRLOG("get_local_params from LLDP failed (%s)\n",
               lldpctl_last_strerror(conn));
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

static cl_timer_t *
ptm_lldp_fetch_timer (cl_timer_t *timer,
                      void *context)
{
    int ret;

    assert(timer != NULL);
    ret = ptm_populate_lldp();
    if (!ret) {
        LOG("%s: fetch from LLDP successful\n", __FUNCTION__);
        cl_timer_destroy(timer);
        ptm_lldp.fetch_timer = NULL;
        return (NULL);
    }
    return (timer);
}

static cl_timer_t *
ptm_lldp_connect_timer (cl_timer_t *timer,
                        void *context)
{
    int ret;

    LOG("%s\n", __FUNCTION__);
    if (timer == NULL) {
        LOG("%s: max timer reached\n", __FUNCTION__);
        exit(PTM_EXITCODE_NO_LLDPD);
    }
    ret = ptm_init_lldp(ptm_lldp.gbl);
    if (!ret) {
        LOG("%s: connection to LLDP successful\n", __FUNCTION__);
        cl_timer_destroy(timer);
        ptm_lldp.connect_timer = NULL;
        ptm_lldp.fetch_timer = cl_timer_create(T_BACKOFF_MAX);
        cl_timer_arm(ptm_lldp.fetch_timer, ptm_lldp_fetch_timer,
                     LLDPD_FETCH_DELAY_AFTER_CONNECT,
                     LLDPD_CONNECT_RETRY_INTERVAL,
                     T_UF_BACKOFF | T_UF_PERIOIDIC);
        if (ptm_lldp.gbl->hostname_changed || ptm_lldp.gbl->mgmt_ip_changed ||
            !ptm_lldp.gbl->conf_init_done)
            ptm_conf_init(ptm_lldp.gbl);
        return (NULL);
    }

    return (timer);
}

void
ptm_finish_lldp ()
{
    if (ptm_lldp.conn) {
        lldpctl_release(ptm_lldp.conn);
        ptm_lldp.conn = NULL;
    }

    /* If select set readfd which then returned 0, ensure we remove
       this fd from the select list, or we get into an infinite loop
       with select waking us up again and again.
    */
    ptm_fd_cleanup(PTM_MODULE_FD(ptm_lldp.gbl, LLDP_MODULE));
    PTM_MODULE_SET_FD(ptm_lldp.gbl, -1, LLDP_MODULE);
    if (ptm_lldp.connect_timer) {
        cl_timer_destroy(ptm_lldp.connect_timer);
        ptm_lldp.connect_timer = NULL;
    }
}

static void
ptm_reinit_lldp ()
{
    if (ptm_lldp.connect_timer == NULL) {
        LOG("creating a timer to retry connect\n");
        ptm_lldp.connect_timer = cl_timer_create(T_BACKOFF_MAX);
        cl_timer_arm(ptm_lldp.connect_timer, ptm_lldp_connect_timer,
                     LLDPD_RECONNECT_INIT_DELAY,
                     LLDPD_CONNECT_RETRY_INTERVAL,
                     T_UF_BACKOFF | T_UF_PERIOIDIC);
    }
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
            LOG("recv error(%s) - connection closed?\n", strerror(errno));
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

/**
 * Register with LLDPD over the LLDPCTL interface to watch for neighbor
 * events and get callbacks.
 */
int
ptm_process_lldp (int in_fd,
                  ptm_sockevent_e se,
                  void *udata)
{
    char buffer[512];
    int rc;

    if (!ptm_lldp.conn) {
        return (-1);
    }

    switch (se) {
    case SOCKEVENT_READ:
        rc = ptm_lldp_recv_cb(ptm_lldp.conn, (const uint8_t *)buffer, 512, NULL);
        if (rc <= 0) {
            ERRLOG("rcv error (%s)\n", strerror(errno));
            ptm_finish_lldp();
            ptm_reinit_lldp();
            return (-1);
        }
        if (lldpctl_recv(ptm_lldp.conn, (const uint8_t *)buffer, rc) < 0) {
            ERRLOG("rcv error (%s)\n", lldpctl_last_strerror(ptm_lldp.conn));
            ptm_finish_lldp();
            ptm_reinit_lldp();
            return (-1);
        }
        break;

    case SOCKEVENT_WRITE:
        if (lldpctl_send(ptm_lldp.conn) < 0) {
            ERRLOG("send error (%s)\n", lldpctl_last_strerror(ptm_lldp.conn));
            ptm_finish_lldp();
            ptm_reinit_lldp();
            return (-1);
        }
        break;

    default:
        break;
    }
    return (0);
}

int
ptm_populate_lldp ()
{
    int ret;

    if (ptm_lldp.conn == NULL) {
        return (-1);
    }

    LOG("%s: watch_cb registering\n", __func__);
    /*
     * start watching for neighbor events.
     */
    if (lldpctl_watch_callback(ptm_lldp.conn, watch_lldp_neighbors_cb,
                               NULL) < 0) {
        ERRLOG("registration to watch neighbors failed (%s)\n",
               lldpctl_last_strerror(ptm_lldp.conn));
        return (-1);
    }

    ret = get_lldp_neighbor_list(ptm_lldp.conn);

    return (ret);
}

/**
 * Entry routine to the LLDP module of PTM. It creates an AF_UNIX socket
 * and connects to LLDPD.
 */
int
ptm_init_lldp (ptm_globals_t *g)
{
    int s;
    int rc;
    int ret = 0;
    const char *name;
    struct sockaddr_un su;
    char old_hostname[HOST_NAME_MAX+1];
    char old_mgmtip[INET6_ADDRSTRLEN];

    ptm_lldp.gbl = g;

    name = lldpctl_get_default_transport();
    if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
        ERRLOG("Create socket failed (%s)\n", strerror(errno));
        return (-1);
    }

    su.sun_family = AF_UNIX;
    memset(su.sun_path, 0, sizeof(su.sun_path));
    strncpy(su.sun_path, name, sizeof(su.sun_path));
    if (connect(s, (struct sockaddr *)&su, sizeof(struct sockaddr_un)) == -1) {
        rc = errno;
        ERRLOG("unable to connect to socket %s\n", name);
        errno = rc;
        close(s);
        ptm_reinit_lldp();
        return (-1);
    }

    fcntl(s, F_SETFL, O_NONBLOCK);
    PTM_MODULE_SET_FD(ptm_lldp.gbl, s, LLDP_MODULE);

    /* create the client connection structure */
    ptm_lldp.conn = lldpctl_new(ptm_lldp_send_cb, ptm_lldp_recv_cb, NULL);
    if (ptm_lldp.conn == NULL) {
        ret = -1;
    }

    /*
     * get local system information from LLDPD. This creates the socket
     * and connects to LLDPD if necessary.
     */
    if (ptm_lldp.gbl->my_hostname == NULL)
        old_hostname[0] = '\0';
    else {
        strncpy(old_hostname, ptm_lldp.gbl->my_hostname, HOST_NAME_MAX);
        old_hostname[HOST_NAME_MAX] = '\0';
    }

    if (ptm_lldp.gbl->my_mgmtip == NULL)
        old_mgmtip[0] = '\0';
    else {
        strncpy(old_mgmtip, ptm_lldp.gbl->my_mgmtip, INET6_ADDRSTRLEN);
        old_hostname[INET6_ADDRSTRLEN] = '\0';
    }

    if (!ret) {
        ret = get_local_params(ptm_lldp.conn);
    }

    if (ret) {
        ptm_finish_lldp();
        ptm_reinit_lldp();
    } else {
        if (strcmp(old_hostname, ptm_lldp.gbl->my_hostname))
            ptm_lldp.gbl->hostname_changed = true;
        if (strcmp(old_mgmtip, ptm_lldp.gbl->my_mgmtip))
            ptm_lldp.gbl->mgmt_ip_changed = true;
    }

    return (ret);
}
