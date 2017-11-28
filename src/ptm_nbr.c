/*********************************************************************
 * Copyright 2013,2014 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
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
    ptm_globals_t  *gbl;
    ptm_event_t    event;
} ptm_nbr_globals_t;

ptm_nbr_globals_t ptm_nbr;

nbr_hash_t *nbr_addr_hash = NULL;
nbr_hash_t *pri_nbr_addr_hash = NULL;

static int ptm_populate_nbr ();
static int ptm_nbr_check_blacklist_interface(const char *iface);
static int ptm_nbr_check_blacklist_ipaddr(const char *ipaddr);
static void _update_nbr_hash(ptm_module_e, char *, char *, bool *, char *);
static void _nbr_process_secondary_addr(void);

/* check for blacklisted IPs
 * For eg. 169.254.0.1, is installed as part of RFC5549 implementation
 */
static int
ptm_nbr_check_blacklist_ipaddr(const char *ipaddr)
{
    int i;
    char *blacklist[] = {"169.254.0.1"};

    if (!ipaddr)
        return 0;

    for (i = 0; i < sizeof(blacklist)/sizeof(char *); i++) {
        if (!strncmp(ipaddr, blacklist[i], strlen(blacklist[i]))) {
            DLOG("blacklisted ipaddr %s\n", ipaddr);
            return 1;
        }
    }
    /* all checks clear */
    return 0;
}

static int
ptm_nbr_check_blacklist_interface(const char *iface)
{
    int i;
    char *blacklist[] = {"eth", "lo"};

    if (!iface)
        return 0;

    for (i = 0; i < sizeof(blacklist)/sizeof(char *); i++) {
        if (!strncmp(iface, blacklist[i], strlen(blacklist[i]))) {
            DLOG("blacklisted interface %s\n", iface);
            return 1;
        }
    }
    /* all checks clear */
    return 0;
}

static void
_update_nbr_event(ptm_module_e type, char *peer_addr,
                  char *port_name, char *rmac_buf)
{
    ptm_event_cleanup(&ptm_nbr.event);
    memset(&ptm_nbr.event, 0x00, sizeof(ptm_nbr.event));

    ptm_nbr.event.module = NBR_MODULE;
    ptm_nbr.event.type = type;
    if (ptm_ipaddr_get_ip_type(peer_addr) == AF_INET)
        ptm_nbr.event.rv4addr = strdup(peer_addr);
    else
        ptm_nbr.event.rv6addr = strdup(peer_addr);
    ptm_nbr.event.liface = strdup(port_name);
    ptm_nbr.event.rmac = strdup(rmac_buf);
}

static int
_extract_event (ptm_event_t *ev)
{
    bool is_primary = FALSE;
    char *peer_addr;

    if(!ev->rv4addr && !ev->rv6addr) {
        /* NULL peer/remote IP passed in - ignore event */
        DLOG("NULL remote IP\n");
        return -1;
    }

    if (!ev->liface || (!ptm_conf_get_port_by_name(ev->liface))) {
        return (-1);
    }

    /* check for blacklisted interfaces (ethx, lo) */
    if (ptm_nbr_check_blacklist_interface(ev->liface))
        return (-1);

    peer_addr = ev->rv4addr?ev->rv4addr:ev->rv6addr;

    /* check for blacklisted IP (eg. 169.254.0.1) */
    if (ptm_nbr_check_blacklist_ipaddr(peer_addr))
        return (-1);

    if (ev->rv6addr && !ptm_ipaddr_is_ipv6_link_local(ev->rv6addr)) {
        DLOG("NBR Recd %s for [%s - %s] - not link-local - ignore\n",
             ptm_event_type_str(ev->type), ev->liface, ev->rv6addr);
        return -1;
    }

    _update_nbr_hash(ev->type, peer_addr, ev->liface, &is_primary, ev->rmac);

    if (!is_primary) {
        DLOG("NBR Recd %s for [%s - %s] - not primary - ignore\n",
             ptm_event_type_str(ev->type), ev->liface, peer_addr);
        return -1;
    }

    _update_nbr_event(ev->type, peer_addr, ev->liface, ev->rmac);

    return (0);
}

static void
_update_nbr_hash(ptm_module_e type, char *peer_addr,
                 char *port_name, bool *ret_primary, char *rmac_buf)
{
    nbr_key_t key;
    pri_nbr_key_t pri_key;
    nbr_hash_t *n_addr, *p_addr;
    bool is_primary = TRUE;
    int afi = ptm_ipaddr_get_ip_type(peer_addr);

    /* find if a primary nbr has been recorded already */
    memset(&pri_key, 0x00, sizeof(pri_key));
    pri_key.afi = afi;
    strcpy(pri_key.port_name, port_name);
    HASH_FIND(afph, pri_nbr_addr_hash, &pri_key, sizeof(pri_key), p_addr);

    memset(&key, 0x00, sizeof(key));
    strcpy(key.addr, peer_addr);
    strcpy(key.port_name, port_name);
    HASH_FIND(aph, nbr_addr_hash, &key, sizeof(key), n_addr);

    if (p_addr &&
        (!n_addr || memcmp(&n_addr->key, &p_addr->key, sizeof(p_addr->key))))
        is_primary = FALSE;

    if (type == EVENT_ADD) {

        DLOG("NBR Received ADD event for addr:port %s - %s [%s]\n",
             peer_addr, port_name,
             is_primary?"primary":"non-primary");

        /* allocate a new nbr */
        if (!n_addr) {
            if ((n_addr = calloc(1, sizeof(*n_addr))) == NULL) {
                ERRLOG("malloc error for new NBR addr:port %s - %s [%s] %m\n",
                       peer_addr, port_name,
                       is_primary?"primary":"non-primary");
                return;
            }
            memcpy(&n_addr->key, &key, sizeof(key));
            n_addr->afi = afi;
            HASH_ADD(aph, nbr_addr_hash, key, sizeof(key), n_addr);

            if (is_primary) {
                /* also add this entry into primary addr hash */
                memcpy(&n_addr->pri_key, &pri_key, sizeof(pri_key));
                HASH_ADD(afph, pri_nbr_addr_hash, pri_key,
                         sizeof(pri_key), n_addr);
            }
        }

        n_addr->is_primary = is_primary;
        strcpy(n_addr->mac, rmac_buf);

    } else if (type == EVENT_DEL) {
        DLOG("NBR Received DEL event for addr:port %s - %s [%s]\n",
             peer_addr, port_name,
             is_primary?"primary":"non-primary");

        if (!n_addr) {
            DLOG("NBR not found addr:port %s - %s \n",
                 peer_addr, port_name);
            return;
        }

        if (is_primary)
            HASH_DELETE(afph, pri_nbr_addr_hash, n_addr);

        HASH_DELETE(aph, nbr_addr_hash, n_addr);
        free(n_addr);
    }

    *ret_primary = is_primary;
}

static int
ptm_handle_nl_nbr_event(ptm_event_t *event)
{
    if (_extract_event(event) != -1) {
        ptm_module_handle_event_cb(&ptm_nbr.event);

        if (ptm_nbr.event.type == EVENT_DEL) {
            /* process secondary (if present) */
            _nbr_process_secondary_addr();
        }
    }
    ptm_event_cleanup(&ptm_nbr.event);

    return 0;
}

static int
ptm_peer_event_nbr(ptm_event_t *event)
{
    char *src_addr = (event->lv4addr) ? event->lv4addr :
                        (event->lv6addr)?event->lv6addr:"N/A";
    char *peer_addr = (event->rv4addr) ? event->rv4addr :
                        (event->rv6addr)?event->rv6addr:"N/A";

    DLOG("Recv [%s] event [%s] vrf [%s] Ifname [%s] Src [%s] Dst [%s]\n",
         ptm_module_string(event->module),
         ptm_event_type_str (event->type),
         (event->vrf_name)?event->vrf_name:"N/A",
         (event->liface)?event->liface:"N/A",
         src_addr, peer_addr);

    switch(event->module) {
        case NETLINK_MODULE:
            ptm_handle_nl_nbr_event(event);
            break;
        default:
            INFOLOG("Recv [%s] event [%s] vrf [%s] peer [%s]: ignore\n",
                    ptm_module_string(event->module),
                    ptm_event_type_str (event->type),
                    (event->vrf_name)?event->vrf_name:"N/A",
                    peer_addr);
    }

    return 0;
}

static int
ptm_populate_nbr ()
{
    nbr_hash_t *n_addr, *tmp;
    int pri_cnt = 0, nbr_cnt = 0;

    INFOLOG("%s: Post Init operations \n", __FUNCTION__);

    PTM_MODULE_PEERCB(ptm_nbr.gbl, NBR_MODULE, NETLINK_MODULE)
                    = ptm_peer_event_nbr;

    PTM_MODULE_SET_STATE(ptm_nbr.gbl, NBR_MODULE, MOD_STATE_POPULATE);

    if (!ptm_nbr.gbl->my_hostname) {
        DLOG("%s: Hostname Not Available - ignore\n", __FUNCTION__);
        return 0;
    }

    /* clear out primary entries */
    HASH_ITER(afph, pri_nbr_addr_hash, n_addr, tmp) {
        HASH_DELETE(afph, pri_nbr_addr_hash, n_addr);
        pri_cnt++;
    }

    /* clear out nbr entries */
    HASH_ITER(aph, nbr_addr_hash, n_addr, tmp) {
        /* stale entry */
        HASH_DELETE(aph, nbr_addr_hash, n_addr);
        free(n_addr);
        nbr_cnt++;
    }

    DLOG("NBR: Cleaned up nbr (%d) primary (%d) entries\n",
         nbr_cnt, pri_cnt);

    return 0;
}

/* routine helps in promoting a secondary peer addr to primary
 * and calls the event handler for the new primary
 *
 * assumed to be called after primary has been deleted
 */
static void
_nbr_process_secondary_addr(void)
{
    nbr_hash_t *n_addr, *tmp;
    int afi;
    ptm_event_t *ev = &ptm_nbr.event;

    afi = AF_INET6;
    if (ev->rv4addr)
        afi = AF_INET;

    HASH_ITER(aph, nbr_addr_hash, n_addr, tmp) {
        if (strcmp(n_addr->key.port_name, ev->liface)) {
            continue;
        }
        if (n_addr->afi == afi) {
            /* same interface, same AFI, different peer
             * promote to primary
             */
            n_addr->is_primary = TRUE;
            n_addr->pri_key.afi = afi;
            strcpy(n_addr->pri_key.port_name, ev->liface);
            HASH_ADD(afph, pri_nbr_addr_hash, pri_key,
                     sizeof(n_addr->pri_key), n_addr);
            INFOLOG("NBR Promote [%s - %s] to primary\n",
                    n_addr->key.addr, ev->liface);
            break;
        }
    }

    if (!n_addr) {
        /* no secondary peer addr promoted to primary */
        return;
    }

    /* found a new primary peer addr - send EVENT_ADD */
    _update_nbr_event(EVENT_ADD, n_addr->key.addr,
                      n_addr->key.port_name, n_addr->mac);

    ptm_module_handle_event_cb(&ptm_nbr.event);
}

int
ptm_init_nbr (ptm_globals_t *g)
{
    ptm_nbr.gbl = g;

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, NBR_MODULE);
    PTM_MODULE_POPULATECB(g, NBR_MODULE) = ptm_populate_nbr;

    PTM_MODULE_SET_STATE(g, NBR_MODULE, MOD_STATE_INITIALIZED);

    return (0);
}

bool
ptm_nbr_is_addr_primary(char *peer_addr, char *port_name)
{
    nbr_hash_t *n_addr;
    nbr_key_t key;

    memset(&key, 0x00, sizeof(key));
    strcpy(key.addr, peer_addr);
    strcpy(key.port_name, port_name);
    HASH_FIND(aph, nbr_addr_hash, &key, sizeof(key), n_addr);

    if (n_addr && n_addr->is_primary)
        return TRUE;

    return FALSE;
}
