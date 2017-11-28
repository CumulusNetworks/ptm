/*********************************************************************
 * Copyright 2016 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * ptm_netlink.[ch] contains code that interacts with rtnetlink
 */

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <net/if.h>

#include "ptm_event.h"
#include "ptm_timer.h"
#include "ptm_conf.h"
#include "ptm_netlink.h"
#include "log.h"

#define PTM_MAX_MSG_PROCESSED   5
#define MAC_STR_SZ 20

#define REPLY_BUFFER    8192
#define SOCKET_BUFSIZE (16 * 1024 * 1024)

#define NETLINK_DUMP_INTERVAL (100 * NSEC_PER_MSEC)

typedef struct nl_req_s {
    struct nlmsghdr hdr;
    struct rtgenmsg gen;
} nl_req_t;

typedef struct {
    ptm_globals_t  *gbl;
    pid_t          pid;
    int            sock;
    int            seq;
    int            neigh_dump_req;
    int            link_dump_req;
    void           *dump_timer;
} ptm_nl_globals_t;

ptm_nl_globals_t ptm_nl;

static int ptm_populate_nl ();
static int ptm_process_nl (int , ptm_sockevent_e , void *);
static void ptm_shutdown_nl(ptm_globals_t *);
static void ptm_nl_dump_timer (cl_timer_t *, void *);
static void ptm_nl_queue_dump_timer();
static void ptm_nl_free_dump_timer();

int
ptm_init_nl (ptm_globals_t *g)
{
    struct sockaddr_nl local;
    int s;
    int flags = 0;
    int sz = SOCKET_BUFSIZE;

    ptm_nl.gbl = g;
    ptm_nl.pid = getpid();

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, NETLINK_MODULE);
    PTM_MODULE_POPULATECB(g, NETLINK_MODULE) = ptm_populate_nl;
    PTM_MODULE_PROCESSCB(g, NETLINK_MODULE) = ptm_process_nl;

    /*
     * prepare netlink socket for kernel/userland communication
     */
    flags = SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK;
    s = socket(AF_NETLINK, flags, NETLINK_ROUTE);
    if (s < 0) {
        ERRLOG("Can't open netlink socket(%m)\n");
	    return (1);
    }
    PTM_MODULE_SET_FD(g, s, NETLINK_MODULE, 0);
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = ptm_nl.pid;
    local.nl_groups = (RTMGRP_NEIGH | RTMGRP_LINK);

    if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
        ERRLOG("cannot bind netlink socket (%m)\n");
        return (-1);
    }

    ptm_nl.sock = s;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sz, sizeof (sz));

    PTM_MODULE_SET_STATE(g, NETLINK_MODULE, MOD_STATE_INITIALIZED);

    return (0);
}

static int
ptm_nl_send(int type)
{
    struct sockaddr_nl kernel;
    struct msghdr rtnl_msg;
    struct iovec io;
    nl_req_t req;

    INFOLOG("Issue Netlink Request (0x%x)\n", type);

    /* RTNL socket is ready for use, prepare and send request */
    memset(&rtnl_msg, 0, sizeof(rtnl_msg));
    memset(&kernel, 0, sizeof(kernel));
    memset(&req, 0, sizeof(req));

    kernel.nl_family = AF_NETLINK;

    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_type = type;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = ++ptm_nl.seq;
    req.hdr.nlmsg_pid = ptm_nl.pid;

    io.iov_base = &req;
    io.iov_len = req.hdr.nlmsg_len;
    rtnl_msg.msg_iov = &io;
    rtnl_msg.msg_iovlen = 1;
    rtnl_msg.msg_name = &kernel;
    rtnl_msg.msg_namelen = sizeof(kernel);

    sendmsg(ptm_nl.sock, (struct msghdr *) &rtnl_msg, 0);
    return (0);
}

static void
_update_nl_addr_event(ptm_event_t *ev, ptm_module_e type,
                      char *peer_addr, char *port_name, char *rmac_buf)
{
    DLOG("netlink nbr event %s [%s : %s]\n",
         ptm_event_type_str(type), port_name, peer_addr);

    memset(ev, 0x00, sizeof(*ev));
    ev->module = NETLINK_MODULE;
    ev->type = type;
    if (ptm_ipaddr_get_ip_type(peer_addr) == AF_INET)
        ev->rv4addr = strdup(peer_addr);
    else
        ev->rv6addr = strdup(peer_addr);
    ev->liface = strdup(port_name);
    ev->rmac = strdup(rmac_buf);
}

static void
_update_nl_link_event(ptm_event_t *ev, ptm_module_e type,
                      char *name, int vrf_id, int is_vrf)
{
    DLOG("netlink interface event %s %s vrf %d\n",
         ptm_event_type_str(type), name, vrf_id);

    memset(ev, 0x00, sizeof(*ev));
    ev->module = NETLINK_MODULE;
    ev->type = type;
    if (is_vrf)
        ev->vrf_name = strdup(name);
    else
        ev->liface = strdup(name);
    ev->vrf_id = vrf_id;
}

static void
ptm_nl_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    while (RTA_OK(rta, len)) {
        if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta,len);
    }
}

static void
ptm_nl_handle_iface (struct nlmsghdr *msg, ptm_event_t *ev,
                     int vrf_id, char *name)
{
    if (msg->nlmsg_type == RTM_NEWLINK) {
        _update_nl_link_event(ev, EVENT_ADD, name, vrf_id, 0);
    } else {
        _update_nl_link_event(ev, EVENT_DEL, name, vrf_id, 0);
    }
}

#define parse_rtattr_nested(tb, max, rta) \
          ptm_nl_parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta))

static int
ptm_nl_handle_vrf (struct nlmsghdr *msg, struct rtattr *linkinfo[],
                   ptm_event_t *ev, char *name)
{
    struct ifinfomsg *ifi;
    struct rtattr *attr[IFLA_VRF_MAX+1] = {0};
    u_int32_t nl_table_id;
    int vrf_id;
    ptm_module_e type;
    char *str;

    ifi = NLMSG_DATA (msg);

    if (!linkinfo[IFLA_INFO_DATA]) {
        DLOG("netlink IFLA_INFO_DATA missing %s\n", name);
        return -1;
    }

    parse_rtattr_nested(attr, IFLA_VRF_MAX, linkinfo[IFLA_INFO_DATA]);
    if (!attr[IFLA_VRF_TABLE]) {
        DLOG("netlink IFLA_VRF_TABLE missing %s\n", name);
        return -1;
    }

    vrf_id = ifi->ifi_index;
    nl_table_id = *(u_int32_t *)RTA_DATA(attr[IFLA_VRF_TABLE]);

    if (msg->nlmsg_type == RTM_NEWLINK) {
        str = "RTM_NEWLINK";
        type = EVENT_ADD;
    } else {
        str = "RTM_DELLINK";
        type = EVENT_DEL;
    }

    DLOG ("netlink %s for vrf %s vrf_id %d tbl %d\n",
          str, name, vrf_id, nl_table_id);
    _update_nl_link_event(ev, type, name, vrf_id, 1);

    return 0;
}

static int
ptm_nl_extract_addr (struct nlmsghdr *n, ptm_event_t *ev)
{

    struct ndmsg *r = NLMSG_DATA(n);
    int len = n->nlmsg_len;
    struct rtattr * tb[NDA_MAX+1];
    struct rtattr *rta;
    char abuf[256] = {0};
    char peer_addr[INET6_ADDRSTRLEN+1] = {0};
    char port_name[MAXNAMELEN+1] = {0};
    ptm_module_e type = MAX_MODULE;
    int tlen;
    unsigned char *rmac;
    char rmac_buf[MAC_STR_SZ] = {0};

    if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
        ERRLOG("Not a NEIGH message: %08x %08x %08x\n",
	       n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
        return -1;
    }

    len -= NLMSG_LENGTH(sizeof(*r));
    if (len < 0) {
        ERRLOG("BUG: wrong nlmsg len %d\n", len);
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
	        if (strlen(abuf))
                strcpy(peer_addr, abuf);
            else {
                DLOG("NULL v6 dst addr\n");
                return (-1);
            }
	        break;
	    case AF_INET:
	        if (strlen(abuf))
	            strcpy(peer_addr, abuf);
            else {
	            DLOG("NULL v4 dst addr\n");
                return (-1);
            }
	        break;
	    default:
	        DLOG("un-handled address family (%x)\n", r->ndm_family);
	        return (-1);
	    }
    }

    if (tb[NDA_LLADDR]) {
        rmac = RTA_DATA(tb[NDA_LLADDR]);
        sprintf(rmac_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                    rmac[0], rmac[1], rmac[2], rmac[3], rmac[4], rmac[5]);
    }

    if (r->ndm_state) {
        int nud = r->ndm_state;
        if ((nud & NUD_REACHABLE) ||
            (nud & NUD_DELAY) ||
            (nud & NUD_STALE) ||
            (nud & NUD_PERMANENT) ||
            (nud & NUD_PROBE)) {
            type = EVENT_ADD;
        } else if ((nud & NUD_INCOMPLETE) ||
                   (nud & NUD_FAILED) ||
                   (nud & NUD_NOARP)) {
            type = EVENT_DEL;
        } else {
	        DLOG("un-handled ndm state (%x)\n", r->ndm_state);
	        return (-1);
        }
    }

    if_indextoname(r->ndm_ifindex, abuf);
    if (strlen(abuf)) {
        strcpy(port_name, abuf);
    } else {
	    DLOG("NBR: NULL local portname\n");
	    return (-1);
    }

    if (!strlen(peer_addr)) {
	    DLOG("NBR: NULL peer addr\n");
	    return (-1);
    }

    _update_nl_addr_event(ev, type, peer_addr, port_name, rmac_buf);

    return (0);
}

static int
ptm_nl_parse_addr(struct nlmsghdr *msg)
{
    ptm_event_t ev = {0};
    int ret;

    ret = ptm_nl_extract_addr (msg, &ev);
    if (ret == 0) {
        ptm_module_handle_event_cb(&ev);
    }
    ptm_event_cleanup(&ev);
    return 0;
}

static int
ptm_nl_extract_link(struct nlmsghdr *msg, ptm_event_t *ev)
{
    struct ifinfomsg *ifi;
    struct rtattr *tb[IFLA_MAX+1] = {};
    struct rtattr *linkinfo[IFLA_MAX+1] = {};
    char *kind = NULL;
    char *slave_kind = NULL;
    char *name = NULL;
    int vrf_id = 0;
    int len;
    int vrf_device = 0;

    ifi = NLMSG_DATA(msg);
    len = msg->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));

    memset(tb, 0, sizeof(tb));
    ptm_nl_parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

    if (!tb[IFLA_IFNAME]) {
        DLOG("netlink interface %d does not have a name - ignore\n",
             ifi->ifi_index);
        return -1;
    }

    name = (char *) RTA_DATA (tb[IFLA_IFNAME]);

    if (tb[IFLA_LINKINFO]) {
        memset (linkinfo, 0, sizeof linkinfo);
        parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

        if (linkinfo[IFLA_INFO_KIND])
            kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);

        if (linkinfo[IFLA_INFO_SLAVE_KIND])
            slave_kind = RTA_DATA(linkinfo[IFLA_INFO_SLAVE_KIND]);

        if (kind && strcmp(kind, "vrf") == 0) {
            if (ptm_nl_handle_vrf (msg, linkinfo, ev, name) < 0)
                return -1;
            vrf_device = 1;
        }
    }

    if (tb[IFLA_MASTER]) {
        if ((kind && strcmp(kind, "vrf") == 0) ||
            (slave_kind && strcmp(slave_kind, "vrf") == 0)) {
            vrf_id = *(u_int32_t *)RTA_DATA(tb[IFLA_MASTER]);
        }
    }

    if (!vrf_device)
        ptm_nl_handle_iface (msg, ev, vrf_id, name);

    return 0;
}

static int
ptm_nl_parse_link(struct nlmsghdr *msg)
{
    ptm_event_t ev = {0};
    int ret;

    ret = ptm_nl_extract_link (msg, &ev);
    if (ret == 0) {
        ptm_module_handle_event_cb(&ev);
    }
    ptm_event_cleanup(&ev);

    return 0;
}

/*
 * recv netlink msg
 */
static int
ptm_nl_recv()
{
    int end = 0;
    volatile int rc = 0;
    int num_msgs = 0;
    struct iovec iov;
    char *reply = NULL;
    int reply_len = REPLY_BUFFER;
    int len;
    struct nlmsghdr *msg = NULL;
    struct sockaddr_nl peer;
    struct msghdr rtnl_reply;

    while (!end) {

        memset(&rtnl_reply, 0, sizeof(rtnl_reply));

        if (!reply) {
            if ((reply = malloc(reply_len)) == NULL) {
                ERRLOG("Can't malloc memory for reply buf %d\n",
                        reply_len);
                end++;
                continue;
            }
        }

        iov.iov_base = reply;
        iov.iov_len = reply_len;
        rtnl_reply.msg_iov = &iov;
        rtnl_reply.msg_iovlen = 1;
        rtnl_reply.msg_name = &peer;
        rtnl_reply.msg_namelen = sizeof(peer);

        len = recvmsg(ptm_nl.sock, &rtnl_reply, 0);
        if (len < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                goto out;
            }
            else if ((errno == ENOMEM) || (errno == ENOBUFS)) {
                free(reply);
                reply = NULL;
                reply_len *=2;
                continue;
            }
            else {
                ERRLOG("%s: recvmsg error (%s), continuing\n", __FUNCTION__,
                        strerror(errno));
                continue;
            }
        }

        if (len == 0) {
            ERRLOG("%s: recvmsg EOF\n", __FUNCTION__);
            break;
        }

        for (msg = (struct nlmsghdr *)reply;
                NLMSG_OK(msg, len);
                msg = NLMSG_NEXT(msg, len)) {
            switch (msg->nlmsg_type) {
                case NLMSG_DONE:
                    DLOG("netlink received done message\n");
                    end++;
                    break;
                case RTM_NEWLINK:
                case RTM_DELLINK:
                    if (ptm_nl_parse_link(msg) < 0) {
                        rc = -1;
                        goto out;
                    }
                    break;
                case RTM_NEWNEIGH:
                case RTM_DELNEIGH:
                    if (ptm_nl_parse_addr(msg) < 0) {
                        rc = -1;
                        goto out;
                    }
                    break;
            } // end switch
        } // end for msg
        num_msgs++;
        if (num_msgs >= PTM_MAX_MSG_PROCESSED) {
            end++;
            continue;
        }
    } // end while

    if (num_msgs) {
        DLOG("%s: processed %d \n", __FUNCTION__, num_msgs);
    }

out:
    if (reply)
        free(reply);
    return rc;
}

static void
ptm_shutdown_nl(ptm_globals_t *g)
{
    INFOLOG("%s: Shutdown called\n", __FUNCTION__);

    ptm_fd_cleanup(ptm_nl.sock);
    ptm_nl.sock = -1;
    ptm_nl.neigh_dump_req = 0;
    ptm_nl.link_dump_req = 0;
    ptm_nl_free_dump_timer();

    PTM_MODULE_SET_FD(g, -1, NETLINK_MODULE, 0);

    PTM_MODULE_SET_STATE(g, NETLINK_MODULE, MOD_STATE_ERROR);

    /* request a re-init */
    ptm_module_request_reinit();
}

static int
ptm_populate_nl ()
{
    INFOLOG("%s: Post Init operations \n", __FUNCTION__);

    PTM_MODULE_SET_STATE(ptm_nl.gbl, NETLINK_MODULE, MOD_STATE_POPULATE);

    ptm_nl.neigh_dump_req = 0;
    ptm_nl.link_dump_req = 0;

    ptm_nl_queue_dump_timer();

    return 0;
}

static int
ptm_process_nl (int in_fd, ptm_sockevent_e se, void *udata)
{
    if (ptm_nl_recv() < 0)
        ptm_shutdown_nl(ptm_nl.gbl);

    return (0);
}

static void
ptm_nl_dump_timer (cl_timer_t *timer, void *context)
{
    int ret = 0;

    DLOG("netlink dump timer BEGIN\n");

    if (!ptm_nl.neigh_dump_req) {
        if (ptm_nl_send(RTM_GETNEIGH) < 0) {
            ret = -1;
            goto out;
        }
        ptm_nl.neigh_dump_req = 1;
    } else if (!ptm_nl.link_dump_req) {
        if (ptm_nl_send(RTM_GETLINK) < 0) {
            ret = -1;
            goto out;
        }
        ptm_nl.link_dump_req = 1;
    }

    if (ptm_nl.link_dump_req && ptm_nl.neigh_dump_req) {
        ptm_nl_free_dump_timer();
    }

out:
    if (ret) {
        ptm_shutdown_nl(ptm_nl.gbl);
    }
}

static void
ptm_nl_queue_dump_timer()
{
    if (!ptm_nl.dump_timer) {
        ptm_nl.dump_timer = cl_timer_create();
        cl_timer_arm(ptm_nl.dump_timer, ptm_nl_dump_timer,
                     NETLINK_DUMP_INTERVAL,
                     (T_UF_PERIODIC | T_UF_NSEC));
    }
}

static void
ptm_nl_free_dump_timer()
{
    if (ptm_nl.dump_timer) {
        cl_timer_destroy(ptm_nl.dump_timer);
        ptm_nl.dump_timer = NULL;
    }
}
