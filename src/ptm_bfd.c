/*********************************************************************
 * Copyright 2014 Cumulus Networks, Inc.  All rights reserved.
 *
 * ptm_bfd.[ch] contains code that interacts with identified neighbors
 * and generate bfd frames, and processes bfd frames from neighbors
 * generating appropriate events when neighbor BFD relationships are 
 * created or destroyed
 */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hash/uthash.h"
#include "ptm_event.h"
#include "ptm_timer.h"
#include "ptm_conf.h"
#include "ptm_bfd.h"
#include "ptm_nbr.h"
#include "ptm_ctl.h"
#include "log.h"

/* iov for BFD control frames */
uint8_t msgbuf[BFD_PKT_LEN];
struct iovec msgiov = {
    &(msgbuf[0]),
    sizeof(msgbuf)
};
uint8_t cmsgbuf[sizeof(struct cmsghdr) + 4];
struct sockaddr_in msgaddr;
struct msghdr msghdr = {
    (void *)&msgaddr,
    sizeof(msgaddr),
    &msgiov,
    1,
    (void *)&cmsgbuf,
    sizeof(cmsgbuf),
    0
};

bfd_session    *session_hash = NULL;    /* Find session from discriminator */
bfd_session    *peer_hash = NULL;       /* Find session from peer address */
bfd_port_parms *parm_hash = NULL;       /* Find params */

int ttlval = BFD_TTL_VAL;
int tosval = BFD_TOS_VAL;
int rcvttl = BFD_RCV_TTL_VAL;

struct timespec bfd_tt_epoch;
uint64_t bfd_epoch_skid = 2000000;     /* this is in NS */

void ptm_timer_cb_bfd(cl_timer_t *timer, void *context);

static void _bfd_modify_ses(bfd_session *bfd, bfd_parm_list *parms);
static int ptm_populate_bfd ();
static int ptm_event_bfd(ptm_event_t *event);
static int ptm_process_bfd(int s, ptm_sockevent_e se, void *udata);
static int ptm_parse_bfd(struct ptm_conf_port *port, char *args);
static int ptm_status_bfd(csv_t *, csv_record_t **, csv_record_t **,
                          char *, void *);
static int ptm_debug_bfd(csv_t *, csv_record_t **, csv_record_t **,
                         char *, void *, char *);
static int ptm_peer_event_bfd(ptm_event_t *event);
static int bfd_parse_detect_mult(bfd_parm_list *parms, char *val);
static int bfd_parse_required_min_rx(bfd_parm_list *parms, char *val);
static int bfd_parse_up_min_tx(bfd_parm_list *parms, char *val);
static int bfd_parse_peer_pri(bfd_parm_list *parms, char *val);
static void ptm_bfd_timer_wheel(void);
static bfd_session *ptm_bfd_ses_find(bfd_pkt_t *cp, struct sockaddr_in *sin);
static bfd_session *ptm_bfd_ses_new(struct ptm_conf_port *iport,
                                    struct in_addr peer, uint32_t remoteDisc);

//#define PTM_DEBUG 1

#if defined(PTM_DEBUG)
static bfd_session *ptm_bfd_iter_sess(bfd_session *bfd);
#endif // DEBUG

bfdParmsKey bfd_parms_key[] = {
    { .key = "upMinTx", .key_cb = bfd_parse_up_min_tx },
    { .key = "requiredMinRx", .key_cb = bfd_parse_required_min_rx },
    { .key = "detectMult", .key_cb = bfd_parse_detect_mult },
    { .key = "peerPri", .key_cb = bfd_parse_peer_pri },
    { .key = NULL, .key_cb = NULL},
};

PtmPeerPriList pri_list[] = {
    { .str = "quagga", .type = QUAGGA_PRI},
    { .str = "nbr", .type = NBR_PRI},
    { .str = NULL },
};

BfdDiagStrList diag_list[] = {
    { .str = "NeighDown", .type = BFD_DIAGNEIGHDOWN},
    { .str = "DetectTime", .type = BFD_DIAGDETECTTIME},
    { .str = "AdminDown", .type = BFD_DIAGADMINDOWN},
    { .str = NULL },
};

static char *get_diag_str(int diag)
{
    for (int i = 0; diag_list[i].str; i++) {
        if (diag_list[i].type == diag)
            return diag_list[i].str;
    }
    return "N/A";
}

BfdStateStrList state_list[] = {
    { .str = "AdminDown", .type = PTM_BFD_ADM_DOWN},
    { .str = "Down", .type = PTM_BFD_DOWN},
    { .str = "Init", .type = PTM_BFD_INIT},
    { .str = "Up", .type = PTM_BFD_UP},
    { .str = NULL },
};

/**
 * Global structure (private to this file) for bookkeeping - init params,
 * input params, statistics, and such.
 */
typedef struct {
    ptm_globals_t   *gbl;
    ptm_event_t     *event;
    cl_timer_t      *fetch_timer;
    int             session_count;
    bfd_parm_list    parms;
} ptm_bfd_globals_t;

ptm_bfd_globals_t ptm_bfd;

#define PTM_BFD_SET_PARM(_f, field, val) (_f)->field = val
#define PTM_BFD_GET_PARM(_f, field) (_f)->field
#define PTM_BFD_SET_GLOBAL_PARM(field, val)                 \
            PTM_BFD_SET_PARM(&ptm_bfd.parms, field, val)
#define PTM_BFD_GET_GLOBAL_PARM(field)                      \
            PTM_BFD_GET_PARM(&ptm_bfd.parms, field)

char *BFD_TEMPLATE_KEY = "bfdtmpl";

void ptm_bfd_ses_dump(void)
{
    bfd_session *bfd, *tmp;

    DLOG("Sessions List\n");
    HASH_ITER(sh, session_hash, bfd, tmp) {
        DLOG("session 0x%x with peer %s\n",
             bfd->discrs.my_discr, inet_ntoa(bfd->peer));
    }
    DLOG("Peers List\n");
    HASH_ITER(ph, peer_hash, bfd, tmp) {
        DLOG("peer %s with session 0x%x\n",
             inet_ntoa(bfd->peer), bfd->discrs.my_discr);
    }
}

uint32_t ptm_bfd_gen_ID(void)
{
    static uint32_t sessionID = 1;
    return(sessionID++);
}

int ptm_bfd_start_timer(struct timespec *epoch)
{
    struct timespec cts;
    int64_t cns, tns, delta;

    /*
     * we have the lowest's create timer run with interval in usec's
     * adjust for rollover ??
     */

    cl_cur_time(&cts);

    cns = timespec_to_ns(&cts);
    tns = timespec_to_ns(epoch);

    delta = (tns - cns);

    if (delta < (int)bfd_epoch_skid) {
        delta = (int)bfd_epoch_skid;
    }

#ifdef DEBUG_TIMERWHEEL
    DLOG("%" PRId64 "\n", delta);
#endif // DEBUG_TIMERWHEEL

    cl_timer_arm(ptm_bfd.fetch_timer, ptm_timer_cb_bfd,
                 delta, (T_UF_PERSIST_SSHOT | T_UF_NSEC));

    return 0;
}

/* should only be used for initialization of the 1st session */
void bfd_init_timer(struct timespec *timer, uint64_t tt_epoch)
{
    assert(bfd_tt_epoch.tv_sec == 0);
    cl_add_time(timer, tt_epoch);
    ptm_bfd_start_timer(timer);
}

/*
 * Update one of the session timers, if the time to event is lower
 * than current lowest, then we need to re-set the timer to next epoch
 */
void bfd_update_timer(struct timespec *timer, uint64_t tt_epoch)
{

    if (tt_epoch == BFD_NULL_TIMER) {
        /* This timer needs to be excluded */
        if (timer) {
            free(timer);
        }
    } else {
        cl_cur_time(timer);
        cl_add_time(timer, tt_epoch);
    }
}

#if defined(PTM_DEBUG)
bfd_session *ptm_bfd_iter_sess(bfd_session *bfd)
{
    bfd_session *sess = session_hash, *tmp;

    if (!bfd)
        return sess;

    HASH_ITER(sh, session_hash, sess, tmp) {
        if (sess == bfd) break;
    }

    /* tmp has the next item in hash */
    return tmp;
}
#endif // DEBUG

static void ptm_shutdown_bfd(ptm_globals_t *g)
{
    ptm_fd_cleanup(PTM_MODULE_FD(g, BFD_MODULE));
    PTM_MODULE_SET_FD(g, -1, BFD_MODULE);

    PTM_MODULE_SET_STATE(g, BFD_MODULE, MOD_STATE_ERROR);

    /* request a re-init */
    ptm_module_request_reinit();
}

int ptm_init_bfd(ptm_globals_t *g)
{
    int s, flags;
    struct sockaddr_in sin;

    ptm_bfd.gbl = g;
    ptm_bfd.session_count = 0;

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, BFD_MODULE);
    PTM_MODULE_EVENTCB(g, BFD_MODULE) = ptm_event_bfd;
    PTM_MODULE_POPULATECB(g, BFD_MODULE) = ptm_populate_bfd;
    PTM_MODULE_PROCESSCB(g, BFD_MODULE) = ptm_process_bfd;
    PTM_MODULE_PARSECB(g, BFD_MODULE) = ptm_parse_bfd;
    PTM_MODULE_STATUSCB(g, BFD_MODULE) = ptm_status_bfd;
    PTM_MODULE_DEBUGCB(g, BFD_MODULE) = ptm_debug_bfd;

    /* Initialize BFD global defaults */
    PTM_BFD_SET_GLOBAL_PARM(up_min_tx, BFD_DEFDESIREDMINTX);
    PTM_BFD_SET_GLOBAL_PARM(timers.required_min_rx, BFD_DEFREQUIREDMINRX);
    PTM_BFD_SET_GLOBAL_PARM(detect_mult, BFD_DEFDETECTMULT);
    PTM_BFD_SET_GLOBAL_PARM(peer_pri, NBR_PRI);

    /* Make UDP socket to receive control packets */
    flags = SOCK_DGRAM | SOCK_CLOEXEC;
    if ((s = socket(PF_INET, flags, IPPROTO_UDP)) < 0) {
        CRITLOG("Can't get receive socket: %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    /* Add socket to select */
    PTM_MODULE_SET_FD(g, s, BFD_MODULE);

    if (setsockopt(s, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
        CRITLOG("Can't set TTL for outgoing packets: %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }
    if (setsockopt(s, SOL_IP, IP_RECVTTL, &rcvttl, sizeof(rcvttl)) < 0) {
        CRITLOG("Can't set receive TTL for incoming packets: %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);

    }
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(BFD_DEFDESTPORT);
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        CRITLOG("Can't bind socket to default port %d: %m\n", BFD_DEFDESTPORT);
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    return 0;
}

#if defined (PKT_DBG)
static void
ptm_dump_bfd_pkt( bfd_pkt_t *cp)
{
    DLOG("myDisc %d, yourDisc %d\n", cp->myDisc, cp->yourDisc);
    DLOG("Control Fields %d\n", cp->byteFields);
}
#endif // PKT_DBG

/*
 * Give a chance to do any post-init operations.
 * registering for nbr events is done here so that other modules
 * have done initializing
 */
static int
ptm_populate_bfd ()
{
    bfd_session *bfd, *tmp;
    bfd_port_parms *entry;
    int old;
    struct ptm_conf_port *port = NULL;

    INFOLOG("%s: Post Init operations \n", __FUNCTION__);

    /* register for peer events */
    PTM_MODULE_PEERCB(ptm_bfd.gbl, BFD_MODULE, NBR_MODULE) = ptm_peer_event_bfd;
    PTM_MODULE_PEERCB(ptm_bfd.gbl, BFD_MODULE, QUAGGA_MODULE) = ptm_peer_event_bfd;

    /* validate existing sessions */
    old = HASH_CNT(ph, peer_hash);
    HASH_ITER(ph, peer_hash, bfd, tmp) {
        if (bfd->nbr_ev) {
            port = ptm_conf_get_port_by_name(bfd->nbr_ev->liface);
            if (!ptm_conf_is_mod_enabled(port, BFD_MODULE)) {
                /* bfd disabled on this port */
                ptm_bfd_ses_dn(bfd, BFD_DIAGADMINDOWN);
                ptm_bfd_ses_del(bfd);
            } else {
                HASH_FIND(ph, parm_hash, bfd->nbr_ev->liface,
                          strlen(bfd->nbr_ev->liface), entry);
                /* update parms */
                _bfd_modify_ses(bfd, (entry)?&entry->parms:&ptm_bfd.parms);
            }
        }
    }

    if (old - HASH_CNT(ph, peer_hash)) {
        DLOG("%s: Deleted stale sessions %d\n",
             __FUNCTION__, old - HASH_CNT(ph, peer_hash));
    }

    return 0;
}


static int ptm_process_bfd(int s, ptm_sockevent_e se,
                    void *udata)
{
    int mlen, new_session = 0;
    struct sockaddr_in *sin;
    bfd_pkt_t *cp;
    struct cmsghdr *cm;
    bfd_session *bfd;
    uint32_t old_xmt_time;
    uint32_t ttlval;
    uint32_t *ttlval_ptr;
    struct ptm_conf_port *port;
    uint8_t old_state;

    if ((mlen = recvmsg(s, &msghdr, 0)) < 0) {
        ERRLOG("Error receiving from BFD socket: %m\n");
        return -1;
    }

    if ((PTM_GET_STATE(ptm_bfd.gbl) == PTM_SHUTDOWN) ||
        (PTM_GET_STATE(ptm_bfd.gbl) == PTM_RECONFIG)) {
        return (-1);
    }

    /* Get source address */
    sin = (struct sockaddr_in *)(msghdr.msg_name);
    /* Get and check TTL */
    cm = CMSG_FIRSTHDR(&msghdr);

    ttlval_ptr = (uint32_t *)CMSG_DATA(cm);
    ttlval = *ttlval_ptr;

    if (ttlval != BFD_TTL_VAL) {
        INFOLOG("Received pkt with invalid TTL %u from %s\n",
                ttlval, inet_ntoa(sin->sin_addr));
        return -1;
    }
    /* Implement RFC 5880 6.8.6 */
    if (mlen < BFD_PKT_LEN) {
        INFOLOG("Received short packet from %s\n",
                inet_ntoa(sin->sin_addr));
        return -1;
    }

    cp = (bfd_pkt_t *)(msghdr.msg_iov->iov_base);

    if (BFD_GETVER(cp->diag) != BFD_VERSION) {
        INFOLOG("Received bad version %d from %s\n", BFD_GETVER(cp->diag),
                inet_ntoa(sin->sin_addr));
        return -1;
    }

    if (cp->detect_mult == 0) {
        INFOLOG("Detect Mult is zero in pkt from %s\n",
                inet_ntoa(sin->sin_addr));
        return -1;
    }

    if ((cp->len < BFD_PKT_LEN) || (cp->len > mlen)) {
        INFOLOG("Invalid length %d in control pkt from %s\n", cp->len,
                inet_ntoa(sin->sin_addr));
        return -1;
    }

//XXX check for multipoint bit ?

    if (cp->discrs.my_discr == 0) {
        INFOLOG("My discriminator is zero in pkt from %s\n",
                inet_ntoa(sin->sin_addr));
        return -1;
    }

    port = ptm_nbr_get_port_from_addr(inet_ntoa(sin->sin_addr));
    if (!port || !ptm_conf_is_mod_enabled(port, BFD_MODULE)) {
        /* dont create session when we dont know for sure */
        return -1;
    }

    if ((bfd = ptm_bfd_ses_find(cp, sin)) == NULL) {
#if 0
        /* create session for
         * unseen neighbor OR local session restarted 
         * XXX this is a RFC violation
         */
        bfd = ptm_bfd_ses_new(sin->sin_addr, cp->discrs.my_discr);
        if (bfd) {
            DLOG("Generating session from remote packet\n");
            new_session = 1;
        } else {
            DLOG("Failed to generate session from remote packet\n");
            return -1;
        }
#else
        DLOG("Failed to generate session from remote packet\n");
        return -1;
#endif // 0

    }


    if ((bfd->discrs.remote_discr != 0) &&
        (bfd->discrs.remote_discr != ntohl(cp->discrs.my_discr))) {
        DLOG("My Discriminator mismatch in pkt"
             "from %s, Expected %d Got %d\n",
             inet_ntoa(sin->sin_addr), bfd->discrs.remote_discr,
             ntohl(cp->discrs.my_discr));
    }

    bfd->discrs.remote_discr = ntohl(cp->discrs.my_discr);
    bfd->remote_ses_state = bfd->ses_state;
    bfd->remote_demand_mode = bfd->demand_mode;

    if (!bfd->demand_mode) {
        /* Compute detect time */
        bfd->detect_TO =
            cp->detect_mult *
            ((bfd->timers.required_min_rx > ntohl(cp->timers.desired_min_tx)) ?
             bfd->timers.required_min_rx : ntohl(cp->timers.desired_min_tx));
        bfd->detect_TO *= NSEC_PER_USEC;
    } else {
        ERRLOG("Unsupport BFD mode detected \n");
    }

    /* State switch from section 6.8.6 */
    old_state = bfd->ses_state;
    if (BFD_GETSTATE(cp->flags) == PTM_BFD_ADM_DOWN) {
        if (bfd->ses_state != PTM_BFD_DOWN) {
            ptm_bfd_ses_dn(bfd, BFD_DIAGNEIGHDOWN);
        }
    } else {
        switch (bfd->ses_state) {
        case (PTM_BFD_DOWN):
            if (BFD_GETSTATE(cp->flags) == PTM_BFD_INIT) {
                ptm_bfd_ses_up(bfd);
            } else if (BFD_GETSTATE(cp->flags) == PTM_BFD_DOWN) {
                bfd->ses_state = PTM_BFD_INIT;
            } /* UP stays in DOWN state */
            break;
        case (PTM_BFD_INIT):
            if (BFD_GETSTATE(cp->flags) == PTM_BFD_INIT ||
                BFD_GETSTATE(cp->flags) == PTM_BFD_UP) {
                ptm_bfd_ses_up(bfd);
            } /* DOWN stays in INIT state */
            break;
        case (PTM_BFD_UP):
            if (BFD_GETSTATE(cp->flags) == PTM_BFD_DOWN) {
                ptm_bfd_ses_dn(bfd, BFD_DIAGNEIGHDOWN);
            } /* INIT and UP stayes in UP state */
            break;
        }
    }

    if (old_state != bfd->ses_state) {
        DLOG("BFD Sess %d [%s] Old State [%s] : New State [%s]\n",
              bfd->discrs.my_discr, inet_ntoa(bfd->peer),
              state_list[old_state].str,
              state_list[bfd->ses_state].str);
    }
//            INFOLOG("Unexpected packet on session 0x%x with peer %s\n",
//                    bfd->discrs.my_discr, inet_ntoa(bfd->peer));
//            ptm_dump_bfd_pkt(cp);

    /* Calculate new transmit time */
    old_xmt_time = bfd->xmt_TO;
    bfd->xmt_TO =
        (bfd->timers.desired_min_tx > ntohl(cp->timers.required_min_rx)) ?
        bfd->timers.desired_min_tx : ntohl(cp->timers.required_min_rx);
    bfd->xmt_TO *= NSEC_PER_USEC;

    /* If transmit time has changed, and too much time until next xmt,
     * restart
     */
    if ((old_xmt_time != bfd->xmt_TO) /* XXX add some skid to this as well */
        || new_session) {
        ptm_bfd_start_xmt_timer(bfd);
    }
    if (!bfd->demand_mode) {
      /* Restart detection timer (packet received) */
        bfd_update_timer(&bfd->detect_timer, bfd->detect_TO);
    } else {
        ERRLOG("Unsupport BFD mode detected \n");
    }
    return 0;
}

void ptm_bfd_detect_TO(bfd_session *bfd)
{
    uint8_t old_state;

    old_state = bfd->ses_state;

    switch (bfd->ses_state) {
    case PTM_BFD_UP:
    case PTM_BFD_INIT:
        ptm_bfd_ses_dn(bfd, BFD_DIAGDETECTTIME);
        /* Session down, restart detect timer so we can clean up later */
        bfd_update_timer(&bfd->detect_timer, bfd->detect_TO);
        INFOLOG("Detect timeout on session 0x%x with peer %s, in state %d\n",
                bfd->discrs.my_discr, inet_ntoa(bfd->peer), bfd->ses_state);
        break;
    default:
        /* Second detect time expiration, zero remote discr (section 6.5.1) */
        bfd->discrs.remote_discr = 0;
        break;
    }

    if (old_state != bfd->ses_state) {
        DLOG("BFD Sess %d [%s] Old State [%s] : New State [%s]\n",
              bfd->discrs.my_discr, inet_ntoa(bfd->peer),
              state_list[old_state].str,
              state_list[bfd->ses_state].str);
    }
}

void _signal_event(bfd_session *bfd,  ptm_event_e type)
{
    bfd->nbr_ev->type = type;
    ptm_module_handle_event_cb(bfd->nbr_ev);
}

void ptm_bfd_ses_dn(bfd_session *bfd, uint8_t diag)
{
    bfd->local_diag = diag;
    bfd->discrs.remote_discr = 0;
    bfd->ses_state = PTM_BFD_DOWN;
    bfd->polling = 0;
    bfd->curr_poll_seq = 0;
    bfd->demand_mode = 0;

    ptm_bfd_snd(bfd, 0);

    if (bfd->nbr_ev)
        _signal_event(bfd, EVENT_DEL);
    INFOLOG("Session 0x%x down to peer %s, Reason %s\n", bfd->discrs.my_discr,
            inet_ntoa(bfd->peer), get_diag_str(bfd->local_diag));

}

void ptm_bfd_ses_up(bfd_session *bfd)
{
    bfd->local_diag = 0;
    bfd->ses_state = PTM_BFD_UP;
    bfd->timers.desired_min_tx = bfd->up_min_tx;
    bfd->polling = 1;

    ptm_bfd_snd(bfd, 0);

    if (bfd->nbr_ev)
        _signal_event(bfd, EVENT_ADD);
    INFOLOG("Session 0x%x up to peer %s\n", bfd->discrs.my_discr,
            inet_ntoa(bfd->peer));
}

bfd_session *ptm_bfd_ses_find(bfd_pkt_t *cp, struct sockaddr_in *sin)
{
    bfd_session *l_bfd;

    if (cp) {
        if (cp->discrs.remote_discr) {
            uint32_t ldisc = ntohl(cp->discrs.remote_discr);
            /* Your discriminator not zero - use it to find session */
            HASH_FIND(sh, session_hash, &ldisc, sizeof(int), l_bfd);
            if (l_bfd && l_bfd->discrs.my_discr == ntohl(cp->discrs.remote_discr)) {
                return(l_bfd);
            }
            DLOG("Can't find session for yourDisc 0x%x from %s\n",
                 ldisc, inet_ntoa(sin->sin_addr));
        } else if (BFD_GETSTATE(cp->flags) == PTM_BFD_DOWN ||
                   BFD_GETSTATE(cp->flags) == PTM_BFD_ADM_DOWN) {
            /* Your discriminator zero - use peer address to find session */
            HASH_FIND(ph, peer_hash, &sin->sin_addr,
                      sizeof(struct in_addr), l_bfd);
            if (l_bfd) {
/* XXX maybe remoteDiscr should be checked for remoteHeard cases */
                return(l_bfd);
            }
        }
        DLOG("Can't find session for peer %s initiated session\n",
                inet_ntoa(sin->sin_addr));
    } else if (sin) {
        HASH_FIND(ph, peer_hash, &sin->sin_addr,
                  sizeof(struct in_addr), l_bfd);
        if (l_bfd) {
            return(l_bfd);
        }
    }

    return(NULL);
}

void ptm_bfd_snd(bfd_session *bfd, int fbit)
{
    bfd_pkt_t cp;
    struct sockaddr_in sin;

    /* Set fields according to section 6.5.7 */
    cp.diag = bfd->local_diag;
    BFD_SETVER(cp.diag, BFD_VERSION);
    cp.flags = 0;
    BFD_SETSTATE(cp.flags, bfd->ses_state);
    BFD_SETDEMANDBIT(cp.flags, BFD_DEF_DEMAND);
    BFD_SETPBIT(cp.flags, bfd->polling);
    BFD_SETFBIT(cp.flags, fbit);
    cp.detect_mult = bfd->detect_mult;
    cp.len = BFD_PKT_LEN;
    cp.discrs.my_discr = htonl(bfd->discrs.my_discr);
    cp.discrs.remote_discr = htonl(bfd->discrs.remote_discr);
    cp.timers.desired_min_tx = htonl(bfd->timers.desired_min_tx);
    cp.timers.required_min_rx = htonl(bfd->timers.required_min_rx);
    cp.timers.required_min_echo = 0;
    sin.sin_family = AF_INET;
    sin.sin_addr = bfd->peer;
    sin.sin_port = htons(BFD_DEFDESTPORT);
    if (sendto(bfd->sock, &cp, BFD_PKT_LEN, 0, (struct sockaddr *)&sin,
               sizeof(struct sockaddr_in)) < 0) {
        ERRLOG("Error sending control pkt: %m\n");
    }
}

static int
ptm_event_bfd(ptm_event_t *event)
{
    struct ptm_conf_port *port = ptm_conf_get_port(event);

    if (!port || !event->rv4addr) return -1;

    if (event->type == EVENT_ADD) {
        INFOLOG("Port %s came up : remote [%s:%s]\n",
             event->liface, port->admin.sys_name, port->admin.port_ident);
        ptm_conf_topo_action(port, TRUE);
    } else if (event->type == EVENT_DEL) {
        INFOLOG("Port %s came down : remote [%s:%s]\n",
             event->liface, port->admin.sys_name, port->admin.port_ident);
        ptm_conf_topo_action(port, FALSE);
    }

    return 0;
}

ptm_event_t *
_cache_event(ptm_event_t *orig)
{
    ptm_event_t *ev = NULL;

    if (orig) {
        ev = ptm_event_clone(orig);
        ev->module = BFD_MODULE;
    }
    return ev;
}

#define UPDATE_FIELD(field) {           \
        if (parms->field != 0) {        \
            bfd->field = parms->field;  \
        }                               \
    }


static void
_bfd_modify_ses(bfd_session *bfd, bfd_parm_list *parms)
{
    UPDATE_FIELD(timers.required_min_rx);
    UPDATE_FIELD(detect_mult);
    UPDATE_FIELD(up_min_tx);
}

static int
ptm_peer_event_bfd(ptm_event_t *event)
{
    struct in_addr daddr;
    struct ptm_conf_port *iport = ptm_conf_get_port(event);
    int ena_mod = ptm_conf_is_mod_enabled(iport, BFD_MODULE);
    bfd_session *bfd = NULL;
    struct sockaddr_in sin;
    bfd_port_parms *entry = NULL;

    if ((!iport) ||
        (!event->rv4addr)) {
        return -1;
    }

    DLOG("%s : Recv peer event %s IP %s\n",
         __FUNCTION__, iport->port_name, event->rv4addr);

    inet_aton(event->rv4addr, &daddr);
    sin.sin_addr.s_addr = daddr.s_addr;

    /* find the BFD session for this local port */
    bfd = ptm_bfd_ses_find(NULL, &sin);

    switch(event->type) {
        case EVENT_ADD :
        case EVENT_UPD :
            /*
             * if BFD inactive => start BFD
             * if BFD active => update ev structure and signal clients
             */
            if (!bfd) {
                if (ena_mod) {
                    bfd = ptm_bfd_ses_new(iport, daddr, 0);
                    if (bfd)
                        bfd->nbr_ev = _cache_event(event);
                }
            } else if (!bfd->nbr_ev) {
                bfd->nbr_ev = _cache_event(event);
                HASH_FIND(ph, parm_hash, iport->port_name,
                          strlen(iport->port_name), entry);
                if (entry) {
                    _bfd_modify_ses(bfd, &entry->parms);
                }
                if (bfd->ses_state == PTM_BFD_UP)
                    _signal_event(bfd, EVENT_ADD);
            }
            break;
        case EVENT_DEL :
            /*
             * if BFD active => remove session
             */
            if (bfd) {
                DLOG("%s : Delete Active bfd session for %s\n",
                    __FUNCTION__, event->rv4addr);
                ptm_bfd_ses_dn(bfd, BFD_DIAGADMINDOWN);
                ptm_bfd_ses_del(bfd);
            }
            break;
        default :
            ERRLOG("Arrived with incomprehensible event for port %s\n",
                   iport->port_name);
    }

    return 0;
}


static bfd_session* ptm_bfd_ses_new(struct ptm_conf_port *iport, 
                                    struct in_addr peer, uint32_t remoteDisc)
{
    bfd_session *bfd, *l_bfd;
    bfd_port_parms *entry = NULL;
    struct sockaddr_in sin;
    int pcount;
    static int srcPort = BFD_SRCPORTINIT;

    /* check to see if this needs a new session */
    HASH_FIND(ph, peer_hash, &peer, sizeof(struct in_addr), l_bfd);
    if (l_bfd) {
        DLOG("Duplicate Neigh event for neigh %s\n", inet_ntoa(l_bfd->peer));
        return NULL;
    }

    /* Get memory */
    if ((bfd = calloc(1, sizeof(bfd_session))) == NULL) {
        INFOLOG("Can't malloc memory for new session: %m\n");
        return NULL;
    }
    /*
     * Get socket for transmitting control packets.  Note that if we could use
     * the destination port (3784) for the source port we wouldn't need a
     * socket per session.
     */
    if ((bfd->sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        ERRLOG("Can't get socket for new session: %m\n");
        free(bfd);
        return NULL;
    }
    /* Set TTL to 255 for all transmitted packets */
    if (setsockopt(bfd->sock, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
        ERRLOG("Can't set TTL for new session: %m\n");
        close(bfd->sock);
        free(bfd);
        return NULL;
    }
    /* Set TOS to CS6 for all transmitted packets */
    if (setsockopt(bfd->sock, IPPROTO_IP, IP_TOS, &tosval,
                   sizeof(tosval)) < 0) {
        ERRLOG("Can't set TOS for new session: %m\n");
        close(bfd->sock);
        free(bfd);
        return NULL;
    }
    /* Find an available source port in the proper range */
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    pcount = 0;
    do {
        if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
            /* Searched all ports, none available */
            INFOLOG("Can't find source port for new session\n");
            close(bfd->sock);
            free(bfd);
            return NULL;
        }
        if (srcPort >= BFD_SRCPORTMAX) srcPort = BFD_SRCPORTINIT;
        sin.sin_port = htons(srcPort++);
    } while (bind(bfd->sock, (struct sockaddr *)&sin, sizeof(sin)) < 0);
    /* Initialize the session */
    bfd->ses_state = PTM_BFD_DOWN;
    bfd->detect_mult = PTM_BFD_GET_GLOBAL_PARM(detect_mult);
    bfd->discrs.my_discr = /* XXX */ptm_bfd_gen_ID();
    bfd->discrs.remote_discr = remoteDisc;
    bfd->up_min_tx = PTM_BFD_GET_GLOBAL_PARM(up_min_tx);
    bfd->timers.desired_min_tx = bfd->up_min_tx;
    bfd->timers.required_min_rx = PTM_BFD_GET_GLOBAL_PARM(timers.required_min_rx);
    bfd->peer = peer;
    bfd->xmt_TO = (bfd->timers.desired_min_tx * NSEC_PER_USEC);
    cl_cur_time(&bfd->xmt_timer);
    bfd->detect_TO = (bfd->detect_mult * bfd->timers.required_min_rx * NSEC_PER_USEC);
    bfd_update_timer(&bfd->detect_timer, bfd->detect_TO);
    HASH_ADD(sh, session_hash, discrs.my_discr, sizeof(int), bfd);
    HASH_ADD(ph, peer_hash, peer, sizeof(struct in_addr), bfd);

    if (iport) {
        HASH_FIND(ph, parm_hash, iport->port_name,
                  strlen(iport->port_name), entry);
        if (entry) {
            _bfd_modify_ses(bfd, &entry->parms);
        }
    }

    /* Start transmitting control packets */
    if (ptm_bfd.session_count == 0) {
        /* setup baseline time */
        bfd_tt_epoch.tv_sec = 0;
        bfd_tt_epoch.tv_nsec = 0;
        ptm_bfd.fetch_timer = cl_timer_create();
        ptm_bfd_start_xmt(bfd);
    } else {
        ptm_bfd_xmt_TO(bfd);
    }
    ptm_bfd.session_count ++;

    INFOLOG("Created new session 0x%x with peer %s\n",
            bfd->discrs.my_discr, inet_ntoa(bfd->peer));
//    ptm_bfd_ses_dump();
    return bfd;
}

void ptm_bfd_start_xmt(bfd_session *bfd)
{

    uint64_t jitter;
    int maxpercent;

    /* Send the scheduled control packet */
    ptm_bfd_snd(bfd, 0);
    /*
     * From section 6.5.2: trasmit interval should be randomly jittered between
     * 75% and 100% of nominal value, unless detect_mult is 1, then should be
     * between 75% and 90%.
     */
    maxpercent = (bfd->detect_mult == 1) ? 16 : 26;
    jitter = (bfd->xmt_TO*(75 + (random() % maxpercent)))/100;
    bfd_init_timer(&bfd->xmt_timer, jitter);
}

void ptm_bfd_xmt_TO(bfd_session *bfd)
{

    /* Send the scheduled control packet */
    ptm_bfd_snd(bfd, 0);
    /* Restart the timer for next time */
    ptm_bfd_start_xmt_timer(bfd);
}

void ptm_bfd_start_xmt_timer(bfd_session *bfd)
{
    uint64_t jitter;
    int maxpercent;

    /*
     * From section 6.5.2: trasmit interval should be randomly jittered between
     * 75% and 100% of nominal value, unless detect_mult is 1, then should be
     * between 75% and 90%.
     */
    maxpercent = (bfd->detect_mult == 1) ? 16 : 26;
    jitter = (bfd->xmt_TO*(75 + (random() % maxpercent)))/100;
/* XXX remove that division above */
    bfd_update_timer(&bfd->xmt_timer, jitter);
}

int ptm_bfd_ses_del(bfd_session *bfd)
{
    INFOLOG("Deleting session 0x%x with peer %s\n",
            bfd->discrs.my_discr, inet_ntoa(bfd->peer));

    HASH_DELETE(ph, peer_hash, bfd);
    HASH_DELETE(sh, session_hash, bfd);

    /* account for timers */
    ptm_bfd.session_count --;
    if (ptm_bfd.session_count == 0) {
        cl_timer_destroy(ptm_bfd.fetch_timer);
    }

    /* free cached nbr events */
    if (bfd->nbr_ev) {
        ptm_event_cleanup(bfd->nbr_ev);
        free(bfd->nbr_ev);
    }

    close(bfd->sock);
    free(bfd);

    return 0;
}

/*  
 * This fuction is the timer loop for bfd events. The actual timer
 * used will be only tracking the time to next epoch, tracked by
 * bfd_tt_epoch.  On epoch expiry every bfd session entry within
 * bfd_epoch_skid, will be acted upon, and the tt_epoch updated if
 * needed
 */
void ptm_bfd_timer_wheel(void)
{
    bfd_session *bfd, *tmp;
    struct timespec cts;
    uint8_t low_init;

    /* get current time and adjust for allowable skid */
    cl_cur_time(&cts);
    cl_add_time(&cts, bfd_epoch_skid);

    if (ptm_bfd.session_count > 0)
    {
        do {
#ifdef DEBUG_TIMERWHEEL
            DLOG("BFD timer fired\n");
#endif // DEBUG_TIMERWHEEL
            low_init = 0;
            HASH_ITER(sh, session_hash, bfd, tmp) {

                /* check expiry status and update timers if needed */
                if (cl_comp_time(&cts, &bfd->xmt_timer) >= 0) {
                    ptm_bfd_xmt_TO(bfd);
                }
                if (bfd->ses_state == PTM_BFD_INIT ||
                    bfd->ses_state == PTM_BFD_UP) {
                    if (cl_comp_time(&cts, &bfd->detect_timer) >= 0) {
                        ptm_bfd_detect_TO(bfd);
                    }
                }

                /* with new timers now, setup running lowest time to epoch */
                if (!low_init) {
                    cl_cp_time(&bfd_tt_epoch, &bfd->xmt_timer);
                    low_init = 1;
                }

                if (cl_comp_time(&bfd_tt_epoch, &bfd->xmt_timer) >= 0) {
                    cl_cp_time(&bfd_tt_epoch, &bfd->xmt_timer);
                }
                if (bfd->ses_state == PTM_BFD_INIT ||
                    bfd->ses_state == PTM_BFD_UP) {
                    if (cl_comp_time(&bfd_tt_epoch, &bfd->detect_timer) >= 0) {
                        cl_cp_time(&bfd_tt_epoch, &bfd->detect_timer);
                    }
                }
            }

        } while (cl_comp_time(&cts, &bfd_tt_epoch) > 0);

        ptm_bfd_start_timer(&bfd_tt_epoch);
    } else {
        DLOG("Entered timer wheel with no session\n");
    }
}

void ptm_timer_cb_bfd(cl_timer_t *timer, void *context)
{
    ptm_bfd_timer_wheel();
}

/*------------------ parse functions ---------------*/

/* need to clear this cache on config reload */
int ptm_clr_parm_bfd()
{
    return 0;
}

static int bfd_parse_peer_pri(bfd_parm_list *parms, char *val)
{
    int i = 0;
    while (pri_list[i].str) {
        if (!strcmp(val, pri_list[i].str)) {
            DLOG("%s: Assigning PeerPri = %s\n", __FUNCTION__, val);
            PTM_BFD_SET_PARM(parms, peer_pri, pri_list[i].type);
            /* we are done */
            return 0;
        }
        i++;
    }

    DLOG("%s: Unsupported value [%s] \n", __FUNCTION__, val);
    return -1;
}

static int bfd_parse_ulong_parm(bfd_parm_list *parms, char *val)
{
    int errno, value;
    char *eptr;

    errno = 0;
    value = strtol(val, &eptr, 10);

    if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN)) ||
        (errno != 0 && value == 0)) {
        ERRLOG("%s: out of range - skipping %d\n", __FUNCTION__, value);
        return -1;
    }

    if (eptr == val) {
        ERRLOG("%s: args not numeric - skipping\n", __FUNCTION__);
        return -1;
    }

    return value;
}

static int bfd_parse_msec_parm(bfd_parm_list *parms, char *val)
{
    int value;

    value = bfd_parse_ulong_parm(parms, val);

    if (((value * MSEC_PER_SEC) >= LONG_MAX) ||
        ((value * MSEC_PER_SEC) <= LONG_MIN)) {
        ERRLOG("%s: out of range - skipping %ld\n", __FUNCTION__,
               (value * MSEC_PER_SEC));
        return -1;
    }
    return (value * MSEC_PER_SEC);
}

static int bfd_parse_detect_mult(bfd_parm_list *parms, char *val)
{
    int value;

    value = bfd_parse_ulong_parm(parms, val);

    if (value < 0)
        return value;

    PTM_BFD_SET_PARM(parms, detect_mult, value);

    DLOG("%s: Assigning detect_mult = %d\n", __FUNCTION__, value);
    return value;
}

static int bfd_parse_required_min_rx(bfd_parm_list *parms, char *val)
{
    int value;

    value = bfd_parse_msec_parm(parms, val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, timers.required_min_rx, value);

    DLOG("%s: Assigning required_min_rx = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_up_min_tx(bfd_parm_list *parms, char *val)
{
    int value;

    value = bfd_parse_msec_parm(parms, val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, up_min_tx, value);

    DLOG("%s: Assigning up_min_tx = %d\n", __FUNCTION__, value);
    return 0;
}

static void
ptm_parse_bfd_template(char *args, char *tmpl)
{
    char val[MAX_ARGLEN];
    tmpl[0] = '\0';
    ptm_conf_find_key_val(BFD_TEMPLATE_KEY, args, val);
    if (strlen(val)) {
        DLOG("%s: Found template [%s] \n", __FUNCTION__, val);
        ptm_conf_get_template_str(val, tmpl);
    }
    return;
}

static int ptm_parse_bfd(struct ptm_conf_port *port, char *args)
{
    bfd_port_parms *entry = NULL, *curr;
    int rval, i, change = 0;
    char in_args[MAX_ARGLEN], tmpl_str[MAX_ARGLEN];
    char val[MAX_ARGLEN];

    DLOG("bfd %s args %s\n", port->port_name,
         (args && strlen(args))?args:"None");

    HASH_FIND(ph, parm_hash, port->port_name, strlen(port->port_name), curr);

    if (!args || !strlen(args)) {
        /* no args supplied - delete port param */
        if (curr) {
            HASH_DELETE(ph, parm_hash, curr);
            free(curr);
        }
        return 0;
    }

    assert(strlen(args) <= MAX_ARGLEN);

    /* we have a hash table of host port instance XXX this will not allow
     * multiple bfd sessions per physical port
     */
    strcpy(in_args, args);
    /* check if there is a template defined  */
    ptm_parse_bfd_template(in_args, tmpl_str);

    if (strlen(tmpl_str)) {
        DLOG("%s: Allow template [%s]\n", __FUNCTION__, tmpl_str);
        strcpy(in_args, tmpl_str);
    }

    entry = (bfd_port_parms *)calloc(1, sizeof(bfd_port_parms));
    if (!entry) {
        ERRLOG("%s: Could not alloc parm entry\n", __FUNCTION__);
        return -1;
    }

    /* Initialize port defaults with global defaults */
    strncpy(entry->port_name, port->port_name, sizeof(port->port_name));
    PTM_BFD_SET_PARM(&entry->parms, detect_mult,
            PTM_BFD_GET_GLOBAL_PARM(detect_mult));
    PTM_BFD_SET_PARM(&entry->parms, up_min_tx,
            PTM_BFD_GET_GLOBAL_PARM(up_min_tx));
    PTM_BFD_SET_PARM(&entry->parms, timers.required_min_rx,
            PTM_BFD_GET_GLOBAL_PARM(timers.required_min_rx));

    /* check for valid params */
    for(i = 0; bfd_parms_key[i].key; i++) {

        ptm_conf_find_key_val(bfd_parms_key[i].key, in_args, val);

        if (strlen(val)) {
            /* found key/val */
            rval = bfd_parms_key[i].key_cb(&entry->parms, val);
            if (!rval)
                change = 1;
        }
    }

    if (change) {
        if (curr) {
            HASH_DELETE(ph, parm_hash, curr);
            free(curr);
        }
        HASH_ADD(ph, parm_hash, port_name,
                 strlen(port->port_name), entry);
    } else {
        free(entry);
    }

    return 0;
}

static int
ptm_status_bfd(csv_t *csv, csv_record_t **hrec, csv_record_t **drec,
               char *opt, void *arg)
{
    struct ptm_conf_port *port = arg;
    char state_buf[MAXNAMELEN];
    char peer_buf[MAXNAMELEN];
    char diag_buf[MAXNAMELEN];
    char det_mult[MAXNAMELEN];
    char tx_timeout[MAXNAMELEN];
    char rx_timeout[MAXNAMELEN];
    bfd_session *bfd, *tmp;
    int detail = FALSE;
    char *dtlstr;

    /* get status cmd has only one option at this point */
    dtlstr = strtok_r(NULL, " ", &opt);

    if(dtlstr && !strcmp(dtlstr, "detail"))
        detail = TRUE;

    /* first the header */
    if (detail)
        *hrec = csv_encode(csv, 6, "BFD state", "BFD peer",
                           "BFD DownDiag", "det_mult", "tx_timeout",
                           "rx_timeout");
    else
        *hrec = csv_encode(csv, 2, "BFD status", "BFD peer");

    if (!*hrec) {
        ERRLOG("%s: Could not allocate csv hdr record\n", __FUNCTION__);
        return (PTM_CMD_ERROR);
    }

    /* loop thru all entries with valid nbr_ev's looking for the
     * local interface == port_name
     */

    /* init to defaults */
    strcpy(state_buf, "N/A");
    strcpy(peer_buf, "N/A");
    strcpy(diag_buf, "N/A");
    sprintf(det_mult, "N/A");
    sprintf(tx_timeout, "N/A");
    sprintf(rx_timeout, "N/A");

    HASH_ITER(ph, peer_hash, bfd, tmp) {
        if ((bfd->nbr_ev) &&
            (strcmp(bfd->nbr_ev->liface, port->port_name) == 0)) {
            if (detail)
                sprintf(state_buf, "%s", state_list[bfd->ses_state].str);
            else
                sprintf(state_buf, "%s",
                    (bfd->ses_state == PTM_BFD_UP)? "pass":"fail");
            sprintf(peer_buf, "%s", inet_ntoa(bfd->peer));
            if (detail) {
                if (bfd->local_diag)
                    sprintf(diag_buf, "%s", get_diag_str(bfd->local_diag));
                sprintf(det_mult, "%d", bfd->detect_mult);
                sprintf(tx_timeout, "%llu",
                        (unsigned long long) bfd->xmt_TO);
                sprintf(rx_timeout, "%llu",
                        (unsigned long long) bfd->detect_TO);
            }
            break;
        }
    }

    if (detail)
        *drec = csv_encode(csv, 6, state_buf, peer_buf, diag_buf,
                           det_mult, tx_timeout, rx_timeout);
    else
        *drec = csv_encode(csv, 2, state_buf, peer_buf);

    if (!*drec) {
        ERRLOG("%s: Could not allocate csv data record\n", __FUNCTION__);
        return (PTM_CMD_ERROR);
    }

    return (PTM_CMD_OK);
}

static int
ptm_debug_bfd(csv_t *csv, csv_record_t **hr, csv_record_t **dr,
              char *opt, void *arg, char *err_str)
{
    bfd_session *bfd, *tmp;
    csv_record_t *hrec, *drec;
    char state_buf[MAXNAMELEN];
    char peer_buf[MAXNAMELEN];
    char diag_buf[MAXNAMELEN];
    char det_mult[MAXNAMELEN];
    char tx_timeout[MAXNAMELEN];
    char rx_timeout[MAXNAMELEN];

    if (!HASH_CNT(ph, peer_hash)) {
        if (err_str) {
            sprintf(err_str,
                    "No BFD sessions . Check connections");
        }

        DLOG("%s: No BFD sessions . Check connections\n", __FUNCTION__);
        return (PTM_CMD_ERROR);
    }

    /* first the header */
    hrec = csv_encode(csv, 7, "port", "peer", "state", "diag",
                      "det_mult", "tx_timeout", "rx_timeout");

    if (!hrec) {
        ERRLOG("%s: Could not allocate csv hdr record\n", __FUNCTION__);
        return (PTM_CMD_ERROR);
    }

    DLOG("peer hash has %d elements\n", HASH_CNT(ph, peer_hash));
    ptm_bfd_ses_dump();

    HASH_ITER(ph, peer_hash, bfd, tmp) {

        sprintf(state_buf, "%s", state_list[bfd->ses_state].str);
        sprintf(peer_buf, "%s", inet_ntoa(bfd->peer));
        sprintf(diag_buf, "%s", get_diag_str(bfd->local_diag));

        sprintf(det_mult, "%d", bfd->detect_mult);
        sprintf(tx_timeout, "%llu",
                (unsigned long long) bfd->xmt_TO);
        sprintf(rx_timeout, "%llu",
                (unsigned long long) bfd->detect_TO);

        /* now the data */
        drec = csv_encode(csv, 7, (bfd->nbr_ev)? bfd->nbr_ev->liface:"Unkn",
                          peer_buf, state_buf, diag_buf, det_mult,
                          tx_timeout, rx_timeout);

        if (!drec) {
            ERRLOG("%s: Could not allocate csv data record\n", __FUNCTION__);
            return (PTM_CMD_ERROR);
        }
    } /* end iter loop */

    return (PTM_CMD_OK);
}
