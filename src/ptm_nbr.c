/*********************************************************************
 * Copyright 2014 Cumulus Networks, Inc.  All rights reserved.
 *
 * ptm_nbr.[ch] contains code that interacts with rtnetlink (NETLINK_ROUTE)
 * messages, extract the required information about the neighbor table (eg. ARP entry)
 * translate them to ptm_event_t abstraction and call the registered callback
 * for each notification.
 */

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <net/if.h>

#include "ptm_event.h"
#include "ptm_conf.h"
#include "ptm_nbr.h"
#include "ptm_bfd.h"
#include "log.h"

#define REPLY_BUFFER 8192

typedef struct nl_req_s nl_req_t;

struct nl_req_s {
    struct nlmsghdr hdr;
    struct rtgenmsg gen;
};

/**
 * Global structure (private to this file) for bookkeeping - init params,
 * input params, statistics, and such.
 */
typedef struct {
    pid_t          pid;
    uint32_t       seq;
    ptm_globals_t  *gbl;
    ptm_event_t    event;
    uint64_t       num_notifs;
} ptm_nbr_globals_t;

ptm_nbr_globals_t ptm_nbr;

nbr_hash_t *nbr_addr_hash = NULL;
nbr_hash_t *nbr_port_hash = NULL;

#define MAC_STR_SZ 14

static int ptm_populate_nbr ();
static int ptm_process_nbr (int in_fd, ptm_sockevent_e se, void *udata);
static int ptm_event_nbr(ptm_event_t *event);

static int
_extract_event (const struct sockaddr_nl *who,
		struct nlmsghdr *n,
		void *arg,
		ptm_event_t *ev)
{
    struct ndmsg *r = NLMSG_DATA(n);
    int len = n->nlmsg_len;
    struct rtattr * tb[NDA_MAX+1];
    struct rtattr *rta;
    char abuf[256];
    char lmbuf[MAC_STR_SZ];
    int tlen;

    if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
        LOG("Not a NEIGH message: %08x %08x %08x\n",
        n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
        return (0);
    }

    memset(ev, 0x00, sizeof(*ev));
    ev->module = NBR_MODULE;

    len -= NLMSG_LENGTH(sizeof(*r));
    if (len < 0) {
        LOG("BUG: wrong nlmsg len %d\n", len);
        return (-1);
    }

    tlen = n->nlmsg_len - NLMSG_LENGTH(sizeof(*r));
    rta = ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))));
    memset(tb, 0, sizeof(struct rtattr *) * (NDA_MAX + 1));
    while (RTA_OK(rta, tlen)) {
        if ((rta->rta_type <= NDA_MAX) && (!tb[rta->rta_type]))
	    tb[rta->rta_type] = rta;
	rta = RTA_NEXT(rta, tlen);
    }
    if (tlen) {
        ERRLOG("!!!Deficit %d, rta_len=%d\n", tlen, rta->rta_len);
	return (-1);
    }

    if (tb[NDA_DST]) {
        inet_ntop(r->ndm_family, RTA_DATA(tb[NDA_DST]),
		  abuf,	sizeof(abuf));
	    switch(r->ndm_family) {
	    case AF_INET6:
	        ev->rv6addr = strdup(abuf);
	        break;
	    case AF_INET:
	        ev->rv4addr = strdup(abuf);
	        break;
	    default:
	        ERRLOG("bad address family\n");
	        break;
	    }
    }

    if (tb[NDA_LLADDR]) {
        memcpy(lmbuf, RTA_DATA(tb[NDA_LLADDR]), ETH_ALEN);
        ev->lmac = strdup(lmbuf);
    }

    if (r->ndm_state) {
        int nud = r->ndm_state;
        if ((nud & NUD_REACHABLE) ||
            (nud & NUD_DELAY) ||
            (nud & NUD_STALE) ||
            (nud & NUD_PERMANENT) ||
            (nud & NUD_PROBE)) {
            ev->type = EVENT_ADD;
        } else if ((nud & NUD_INCOMPLETE) ||
                   (nud & NUD_FAILED) ||
                   (nud & NUD_NOARP)) {
            ev->type = EVENT_DEL;
        } else {
            ev->type = EVENT_UNKNOWN;
        }
    }

    if_indextoname(r->ndm_ifindex, abuf);
    ev->liface = NULL;
    if (strlen(abuf))
        ev->liface = strdup(abuf);

    return (0);
}

/* XXX needs to be in ptm_netlink.c */
static int
_send_netlink_request (uint16_t type)
{
    struct sockaddr_nl kernel;
    struct msghdr rtnl_msg;
    struct iovec io;
    nl_req_t req;

    /* RTNL socket is ready for use, prepare and send request */
    memset(&rtnl_msg, 0, sizeof(rtnl_msg));
    memset(&kernel, 0, sizeof(kernel));
    memset(&req, 0, sizeof(req));

    kernel.nl_family = AF_NETLINK;

    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_type = type;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = ptm_nbr.seq;
    ptm_nbr.seq++;
    req.hdr.nlmsg_pid = ptm_nbr.pid;

    io.iov_base = &req;
    io.iov_len = req.hdr.nlmsg_len;
    rtnl_msg.msg_iov = &io;
    rtnl_msg.msg_iovlen = 1;
    rtnl_msg.msg_name = &kernel;
    rtnl_msg.msg_namelen = sizeof(kernel);

    sendmsg(PTM_MODULE_FD(ptm_nbr.gbl, NBR_MODULE),
	    (struct msghdr *) &rtnl_msg, 0);
    return (0);
}

#define UPDATE_FIELD(d, s) \
            if (event->s) strncpy(n_addr->d, event->s, sizeof(n_addr->d))
#define EXTRACT_FIELD(d, s) \
            if (n_addr->s) event->d = strdup(n_addr->s)

/**
 * Process events for NBR
 */
static int
ptm_event_nbr(ptm_event_t *event)
{
    ptm_conf_port_t *port = ptm_conf_get_port(event);
    nbr_hash_t *n_addr;
    nbr_hash_t *n_port;
    int existing = FALSE;

    if (!port || !event->rv4addr)
        return -1;

    HASH_FIND(ah, nbr_port_hash, event->liface,
              strlen(event->liface), n_port);

    HASH_FIND(ah, nbr_addr_hash, event->rv4addr,
              strlen(event->rv4addr), n_addr);

    if (n_port != n_addr) {
        /* some mismatch - ignore this event */
        return -1;
    } else if (n_port) {
        existing = TRUE;
    }

    if ((event->type == EVENT_ADD) ||
        (event->type == EVENT_UPD)) {

        DLOG("NBR Received %s event for addr:port %s:%s\n",
             (event->type == EVENT_ADD)?"ADD":"UPD",
             event->rv4addr, port->port_name);

        /* allocate a new nbr */
        if (!n_addr) {
            if ((n_addr = calloc(1, sizeof(*n_addr))) == NULL) {
                ERRLOG("Can't malloc memory for new NBR addr:port %s:%s\n",
                       event->rv4addr, port->port_name);
                return -1;
            }
        }

        UPDATE_FIELD(port_name, liface);
        UPDATE_FIELD(ipv4_addr, rv4addr);
        UPDATE_FIELD(ipv6_addr, rv6addr);
        n_addr->event = ptm_event_clone(event);

        if (!existing) {
            HASH_ADD(ah, nbr_addr_hash, ipv4_addr,
                 strlen(n_addr->ipv4_addr), n_addr);
            HASH_ADD(ph, nbr_port_hash, port_name,
                 strlen(n_addr->port_name), n_addr);
        }

    } else if (event->type == EVENT_DEL) {
        DLOG("NBR Received DEL event for addr:port %s:%s\n",
              event->rv4addr, port->port_name);

        if (n_addr) {
            HASH_DELETE(ah, nbr_addr_hash, n_addr);
            HASH_DELETE(ph, nbr_port_hash, n_addr);
            ptm_event_cleanup(n_addr->event);
            free(n_addr->event);
            free(n_addr);
        }

    } else {
        DLOG("NBR Received UNK event for addr:port %s:%s\n",
              event->rv4addr, port->port_name);
        return -1;
    }

    return(0);
}

static int
ptm_populate_nbr ()
{
    nbr_hash_t *n_addr, *tmp;
    int old;

    INFOLOG("%s: Post Init operations \n", __FUNCTION__);

    old = HASH_CNT(ah, nbr_addr_hash);

    if (old) {
        /* clear out old entries */
        HASH_ITER(ah, nbr_addr_hash, n_addr, tmp) {
            /* stale entry */
            HASH_DELETE(ah, nbr_addr_hash, n_addr);
            HASH_DELETE(ph, nbr_port_hash, n_addr);
            ptm_event_cleanup(n_addr->event);
            free(n_addr);
        }

        DLOG("%s: Cleaned up %d stale entries\n", __FUNCTION__, old);

        /* request new dump */
        _send_netlink_request(RTM_GETNEIGH);
    }

    return 0;
}

static int
ptm_process_nbr (int in_fd, ptm_sockevent_e se, void *udata)
{
    int end = 0;
    char reply[REPLY_BUFFER];
    struct iovec io;
    struct sockaddr_nl kernel;

    if ((PTM_GET_STATE(ptm_nbr.gbl) == PTM_SHUTDOWN) ||
        (PTM_GET_STATE(ptm_nbr.gbl) == PTM_RECONFIG)) {
        return (-1);
    }

    assert(in_fd == PTM_MODULE_FD(ptm_nbr.gbl, NBR_MODULE));

    /* parse reply */
    while (!end) {
        int len;
        struct nlmsghdr *msg_ptr;
        struct msghdr rtnl_reply;
        struct iovec io_reply;

        memset(&io_reply, 0, sizeof(io_reply));
        memset(&rtnl_reply, 0, sizeof(rtnl_reply));

        io.iov_base = reply;
        io.iov_len = REPLY_BUFFER;
        rtnl_reply.msg_iov = &io;
        rtnl_reply.msg_iovlen = 1;
        rtnl_reply.msg_name = &kernel;
        rtnl_reply.msg_namelen = sizeof(kernel);

        len = recvmsg(PTM_MODULE_FD(ptm_nbr.gbl, NBR_MODULE), &rtnl_reply, 0);
        if (len < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
#if 0
                LOG("%s: recvmsg error (%s), breaking\n", __FUNCTION__,
                        strerror(errno));
#endif
                break;
            }
            else {
                LOG("%s: recvmsg error (%s), continuing\n", __FUNCTION__,
                        strerror(errno));
                continue;
            }
        }

        if (len == 0) {
            LOG("%s: recvmsg EOF\n", __FUNCTION__);
            break;
        }

        if (len) {
            for (msg_ptr = (struct nlmsghdr *) reply;
                    NLMSG_OK(msg_ptr, (unsigned int) len);
                    msg_ptr = NLMSG_NEXT(msg_ptr, len)) {

                switch(msg_ptr->nlmsg_type) {
                    case NLMSG_DONE:
                        end++;
                        break;
                    case RTM_NEWNEIGH:
                    case RTM_GETNEIGH: /* XXX why would we get this ? */
                    case RTM_DELNEIGH:
                        _extract_event(NULL, msg_ptr, NULL, &ptm_nbr.event);
                        /*
                         * XXX ev.rv6addr, ev.rv4addr, ev.liface XX not
                         * needed, as routing should handle this
                         *
                         * XXX A little messed up, we should store in binary
                         * format and let modules expand into string
                         * format
                         */
                        ptm_module_handle_event_cb(&ptm_nbr.event);
                        ptm_event_cleanup(&ptm_nbr.event);
                        break;
                    default:
                        ERRLOG("message type %d, length %d\n",
                                msg_ptr->nlmsg_type,
                                msg_ptr->nlmsg_len);
                        break;
                }
            }
        }
    }

    return (0);
}

int
ptm_init_nbr (ptm_globals_t *g)
{
    struct sockaddr_nl local;
    int fd;
    int flags = 0;

    ptm_nbr.gbl = g;
    ptm_nbr.pid = getpid();
    ptm_nbr.seq = 1;

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, NBR_MODULE);
    PTM_MODULE_POPULATECB(g, NBR_MODULE) = ptm_populate_nbr;
    PTM_MODULE_PROCESSCB(g, NBR_MODULE) = ptm_process_nbr;
    PTM_MODULE_EVENTCB(g, NBR_MODULE) = ptm_event_nbr;

    /*
     * prepare netlink socket for kernel/userland communication
     */
    flags = SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK;
    fd = socket(AF_NETLINK, flags, NETLINK_ROUTE);
    if (fd < 0) {
        ERRLOG("Can't open netlink socket(%s)\n", strerror(errno));
	return (1);
    }
    PTM_MODULE_SET_FD(g, fd, NBR_MODULE);
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = ptm_nbr.pid;
    local.nl_groups = RTMGRP_NEIGH;

    if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) {
        ERRLOG("cannot bind (%s), are you root ?", strerror(errno));
        return (-1);
    }

    _send_netlink_request(RTM_GETNEIGH);

    return (0);
}

void
ptm_nbr_get_event_by_port(char *port_name, ptm_event_t **event)
{
    nbr_hash_t *n_addr;

    *event = NULL;
    HASH_FIND(ph, nbr_port_hash, port_name,
              strlen(port_name), n_addr);

    if (n_addr) {
        *event = ptm_event_clone(n_addr->event);
    }
}

ptm_conf_port_t *
ptm_nbr_get_port_from_addr(char *addr)
{
    ptm_conf_port_t *port = NULL;
    nbr_hash_t *n_addr;

    HASH_FIND(ah, nbr_addr_hash, addr, strlen(addr), n_addr);

    if (n_addr) {
        port = ptm_conf_get_port_by_name(n_addr->port_name);
    }

    return port;
}
