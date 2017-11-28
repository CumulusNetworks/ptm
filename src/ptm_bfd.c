/*********************************************************************
 * Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * ptm_bfd.[ch] implements the BFD protocol and interacts with
 * other ptm modules
 *
 * Poll Mode is not supported
 *
 * Authors
 * -------
 * Shrijeet Mukherjee [shm@cumulusnetworks.com]
 * Kanna Rajagopal [kanna@cumulusnetworks.com]
 * Radhika Mahankali [Radhika@cumulusnetworks.com]
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
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include "hash/uthash.h"
#include "ptm_event.h"
#include "ptm_timer.h"
#include "ptm_conf.h"
#include "ptm_lib.h"
#include "ptm_bfd.h"
#include "ptm_nbr.h"
#include "ptm_ctl.h"
#include "log.h"
#include "ptm_util.h"

/* iov for BFD control frames */
#define CMSG_HDR_LEN sizeof(struct cmsghdr)
#define CMSG_TTL_LEN (CMSG_HDR_LEN + sizeof(uint32_t))
#define CMSG_IN_PKT_INFO_LEN (CMSG_HDR_LEN + sizeof(struct in_pktinfo) + 4)
#define CMSG_IN6_PKT_INFO_LEN (CMSG_HDR_LEN + sizeof(struct in6_addr) + sizeof(int) + 4)

uint8_t msgbuf[BFD_PKT_LEN];
struct iovec msgiov = {
    &(msgbuf[0]),
    sizeof(msgbuf)
};
uint8_t cmsgbuf[CMSG_TTL_LEN + CMSG_IN_PKT_INFO_LEN];

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

uint8_t cmsgbuf6[CMSG_TTL_LEN + CMSG_IN6_PKT_INFO_LEN];

struct sockaddr_in6 msgaddr6;
struct msghdr msghdr6 = {
    (void *)&msgaddr6,
    sizeof(msgaddr6),
    &msgiov,
    1,
    (void *)&cmsgbuf6,
    sizeof(cmsgbuf6),
    0
};

/* Berkeley Packet filter code to filter out BFD Echo packets.
 * tcpdump -dd "(udp dst port 3785)"
 */
static struct sock_filter bfd_echo_filter[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 4, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 11, 0x00000011 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 8, 9, 0x00000ec9 },
    { 0x15, 0, 8, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 6, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 4, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000ec9 },
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 },
};

/* Berkeley Packet filter code to filter out BFD vxlan packets.
 * tcpdump -dd "(udp dst port 4789)"
 */
static struct sock_filter bfd_vxlan_filter[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 4, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 11, 0x00000011 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 8, 9, 0x000012b5 },
    { 0x15, 0, 8, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 6, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 4, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x000012b5 },
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 },
};

/* sync interval expressed in sec */
#define PTM_BFD_CLIENT_SYNC_INTERVAL 20

/* sess pend interval expressed in sec */
#define PTM_BFD_SESS_PEND_INTERVAL 2

char const *PTM_BFD_SESS_UP_FILE = "bfd-sess-up";
char const *PTM_BFD_SESS_DOWN_FILE = "bfd-sess-down";

bfd_session    *session_hash = NULL;    /* Find session from discriminator */
bfd_session    *peer_hash = NULL;       /* Find session from peer address */
bfd_session    *local_peer_hash = NULL; /* Find session from peer and local
                                         * address */
bfd_sess_parms *topo_parm_hash = NULL;  /* Find topo file based params */
bfd_sess_parms *sess_parm_hash = NULL;  /* Find sess params per dst ip */

struct bfd_vrf *vrf_hash = NULL;
struct bfd_iface *iface_hash = NULL;

int ttlval = BFD_TTL_VAL;
int tosval = BFD_TOS_VAL;
int rcvttl = BFD_RCV_TTL_VAL;
int pktinfo = BFD_PKT_INFO_VAL;
int ipv6_pktinfo = BFD_IPV6_PKT_INFO_VAL;
int ipv6_only = BFD_IPV6_ONLY_VAL;

struct timespec bfd_tt_epoch;
uint64_t bfd_epoch_skid = 2000000;     /* this is in NS */

void ptm_timer_cb_bfd(cl_timer_t *timer, void *context);

static void ptm_bfd_update_sess_params(bfd_session *);
static int ptm_populate_bfd ();
static int ptm_event_bfd(ptm_event_t *event);
static int ptm_process_bfd(int s, ptm_sockevent_e se, void *udata);
static int ptm_parse_bfd(struct ptm_conf_port *port, char *args);
static int ptm_status_bfd(void *, void *, void *);
static int ptm_peer_event_bfd(ptm_event_t *event);
static int bfd_parse_detect_mult(bfd_parms_list *parms, char *val);
static int bfd_parse_required_min_rx(bfd_parms_list *parms, char *val);
static int bfd_parse_up_min_tx(bfd_parms_list *parms, char *val);
static int bfd_parse_required_min_echo(bfd_parms_list *parms, char *val);
static void ptm_bfd_timer_wheel(void);
static bfd_session *ptm_bfd_sess_find(bfd_pkt_t *cp, char *port_name,
                                     ptm_ipaddr peer, ptm_ipaddr local,
                                     char *vrf_name, bool is_mhop);
static bfd_session *ptm_bfd_sess_new(ptm_event_t *event,
                                    ptm_ipaddr peer,
                                    ptm_ipaddr local,
                                    bool is_mhop,
                                    bfd_sess_parms *sess_parms);
static void ptm_bfd_ses_del(bfd_session *bfd);
static int ptm_bfd_echo_sock_init(void);
static int ptm_bfd_process_echo_pkt(int s, ptm_sockevent_e se, void *udata);
static void ptm_bfd_echo_xmt_TO(bfd_session *bfd);
static void ptm_bfd_send_evt_TO(bfd_session *bfd);
static int ptm_bfd_fetch_ifindex (char *if_name, int sd);
static void _fetch_portname_from_ifindex (int ,int ,char *);
static void ptm_bfd_fetch_local_mac (char *if_name, int sd, uint8_t *local_mac);
static int bfd_parse_slow_min_tx(bfd_parms_list *parms, char *val);
static int bfd_parse_src_ipaddr(bfd_parms_list *parms, char *val);
static int bfd_parse_dst_ipaddr(bfd_parms_list *parms, char *val);
static int bfd_parse_ifname(bfd_parms_list *parms, char *val);
static int bfd_parse_vnid(bfd_parms_list *parms, char *val);
static int bfd_parse_multi_hop(bfd_parms_list *parms, char *val);
static int bfd_parse_local_dst_mac(bfd_parms_list *parms, char *val);
static int bfd_parse_local_dst_ip(bfd_parms_list *parms, char *val);
static int bfd_parse_remote_dst_mac(bfd_parms_list *parms, char *val);
static int bfd_parse_remote_dst_ip(bfd_parms_list *parms, char *val);
static int bfd_parse_decay_min_rx(bfd_parms_list *parms, char *val);
static int bfd_parse_forwarding_if_rx(bfd_parms_list *parms, char *val);
static int bfd_parse_cpath_down(bfd_parms_list *parms, char *val);
static int bfd_parse_check_tnl_key(bfd_parms_list *parms, char *val);
static int bfd_parse_max_hop_cnt(bfd_parms_list *parms, char *val);
static int bfd_parse_afi(bfd_parms_list *parms, char *val);
static int bfd_parse_send_event(bfd_parms_list *parms, char *val);
static int bfd_parse_echo_support(bfd_parms_list *parms, char *val);
static int bfd_parse_vrf_name(bfd_parms_list *parms, char *val);
static void ptm_bfd_echo_detect_TO(bfd_session *bfd);
static void ptm_bfd_echo_start(bfd_session *bfd);
static void ptm_bfd_echo_stop(bfd_session *bfd, int polling);
static int ptm_bfd_vxlan_sock_init(void);
void ptm_bfd_vxlan_pkt_snd(bfd_session *bfd, int f_bit);
static bfd_pkt_t *ptm_bfd_process_vxlan_pkt(int s, ptm_sockevent_e se,
                        void *udata, int *ifindex,
                        struct sockaddr_in *sin,
                        bfd_session_vxlan_info_t *vxlan_info,
                        uint8_t *rx_pkt,
                        int *mlen);
bool ptm_bfd_validate_vxlan_pkt(bfd_session *bfd,
                           bfd_session_vxlan_info_t *vxlan_info);
static bfd_sess_parms *ptm_bfd_alloc_sess_parms(void);
static void ptm_bfd_client_timer(cl_timer_t *timer, void *context);
static void ptm_bfd_start_client_timer(void);
static void ptm_bfd_extend_client_timer(void);
static void ptm_bfd_stop_client_timer(void);
static void ptm_bfd_sess_pend_timer(cl_timer_t *timer, void *context);
static void ptm_bfd_start_sess_pend_timer(void);
static void ptm_bfd_stop_sess_pend_timer(void);
static ptm_bfd_client_t *_get_client_info_by_name(char *name);
static ptm_bfd_client_t *_get_client_info_by_idx(int idx);
static void _decr_client_num_sessions(char *name, bool pend);
static void _incr_client_num_sessions(char *name, bool pend);
static ptm_bfd_client_t *_add_client_info(char *name, int seqid);
static void _del_client_info(char *name);
static void handle_bfd_event(ptm_module_e , bfd_sess_parms *, ptm_event_e);
static int ptm_bfd_get_client_list(ptm_client_t *, void *, char *);
static int ptm_bfd_get_client_sess(ptm_client_t *, void *, char *);
static bfd_sess_parms *ptm_clone_bfd_params(bfd_sess_parms *);
static int ptm_bfd_get_vrf_name(char *port_name, char *vrf_name);

//#define PTM_DEBUG 1

#define MAX_CLIENTS             16
#define CLIENT_NAME_DFLT        "ptm"
#define CLIENT_SEQID_DFLT       255
#define CLIENT_NAME             "client"
#define CLIENT_SEQ_ID           "seqid"
#define MAX_SESS_PEND_PER_LOOP  16

bfd_parms_key bfd_parms_key_tbl[] = {
    { .key = "upMinTx", .key_cb = bfd_parse_up_min_tx },
    { .key = "requiredMinRx", .key_cb = bfd_parse_required_min_rx },
    { .key = "detectMult", .key_cb = bfd_parse_detect_mult },
    { .key = "echoMinRx", .key_cb = bfd_parse_required_min_echo },
    { .key = "slowMinTx", .key_cb = bfd_parse_slow_min_tx },
    { .key = "srcIPaddr", .key_cb = bfd_parse_src_ipaddr },
    { .key = "dstIPaddr", .key_cb = bfd_parse_dst_ipaddr },
    { .key = "ifName", .key_cb = bfd_parse_ifname },
    { .key = "vnid", .key_cb = bfd_parse_vnid },
    { .key = "multiHop", .key_cb = bfd_parse_multi_hop },
    { .key = "local_dst_mac", .key_cb = bfd_parse_local_dst_mac },
    { .key = "local_dst_ip", .key_cb = bfd_parse_local_dst_ip },
    { .key = "remote_dst_mac", .key_cb = bfd_parse_remote_dst_mac },
    { .key = "remote_dst_ip", .key_cb = bfd_parse_remote_dst_ip },
    { .key = "decay_min_rx", .key_cb = bfd_parse_decay_min_rx },
    { .key = "forwarding_if_rx", .key_cb = bfd_parse_forwarding_if_rx },
    { .key = "cpath_down", .key_cb = bfd_parse_cpath_down },
    { .key = "check_tnl_key", .key_cb = bfd_parse_check_tnl_key },
    { .key = "maxHopCnt", .key_cb = bfd_parse_max_hop_cnt },
    { .key = "afi", .key_cb = bfd_parse_afi },
    { .key = "sendEvent", .key_cb = bfd_parse_send_event },
    { .key = "echoSupport", .key_cb = bfd_parse_echo_support },
    { .key = "vrfName", .key_cb = bfd_parse_vrf_name },
    { .key = NULL, .key_cb = NULL},
};

bfd_diag_str_list diag_list[] = {
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

bfd_state_str_list state_list[] = {
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
    cl_timer_t      *fetch_timer;
    int             session_count;
    bfd_parms_list   parms;
    int             shop_sock;
    int             mhop_sock;
    int             echo_sock;
    int             vxlan_sock;
    int             shopv6_sock;
    int             mhopv6_sock;
    ptm_event_t     event;
    cl_timer_t      *client_timer;
    cl_timer_t      *sess_pend_timer;
    ptm_bfd_client_t clients[MAX_CLIENTS];
    int             num_clients;
} ptm_bfd_globals_t;

ptm_bfd_globals_t ptm_bfd;

typedef struct bfd_raw_echo_pkt_s {
    struct iphdr    ip;
    struct udphdr   udp;
    bfd_echo_pkt_t  data;
} bfd_raw_echo_pkt_t;

typedef struct bfd_raw_ctrl_pkt_s {
    struct iphdr    ip;
    struct udphdr   udp;
    bfd_pkt_t       data;
} bfd_raw_ctrl_pkt_t;

typedef struct vxlan_hdr_s {
    uint32_t flags;
    uint32_t vnid;
} vxlan_hdr_t;

#define IP_ECHO_PKT_LEN (IP_HDR_LEN + UDP_HDR_LEN + BFD_ECHO_PKT_LEN)
#define UDP_ECHO_PKT_LEN (UDP_HDR_LEN + BFD_ECHO_PKT_LEN)
#define IP_CTRL_PKT_LEN (IP_HDR_LEN + UDP_HDR_LEN + BFD_PKT_LEN)
#define UDP_CTRL_PKT_LEN (UDP_HDR_LEN + BFD_PKT_LEN)

#define PTM_BFD_STRCPY_PARM(_f, field, val) strcpy((_f)->field, (val))
#define PTM_BFD_MEMCPY_PARM(_f, field, val) \
            memcpy(&(_f)->field, &(val), sizeof((_f)->field))
#define PTM_BFD_SET_PARM(_f, field, val) (_f)->field = (val)
#define PTM_BFD_GET_PARM(_f, field) (_f)->field
#define PTM_BFD_SET_GLOBAL_PARM(field, val)                 \
            PTM_BFD_SET_PARM(&ptm_bfd.parms, field, (val))
#define PTM_BFD_GET_GLOBAL_PARM(field)                      \
            PTM_BFD_GET_PARM(&ptm_bfd.parms, field)

char *BFD_TEMPLATE_KEY = "bfdtmpl";

uint8_t bfd_def_vxlan_dmac [] =  {0x00, 0x23, 0x20, 0x00, 0x00, 0x01};

typedef struct udp_psuedo_header_s {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t len;
} udp_psuedo_header_t;

#define UDP_PSUEDO_HDR_LEN sizeof(udp_psuedo_header_t)

uint16_t
checksum (uint16_t *buf, int len)
{
    int nbytes = len;
    int sum = 0;
    uint16_t csum = 0;
    int size = sizeof(uint16_t);

    while (nbytes > 1) {
        sum += *buf++;
        nbytes -= size;
    }

    if (nbytes == 1) {
        *(uint8_t *) (&csum) = *(uint8_t *) buf;
        sum += csum;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    csum = ~sum;
    return (csum);
}

uint16_t
udp4_checksum (struct iphdr *iph, uint8_t *buf, int len)
{
    char *ptr;
    udp_psuedo_header_t pudp_hdr;
    uint16_t csum;

    pudp_hdr.saddr = iph->saddr;
    pudp_hdr.daddr = iph->daddr;
    pudp_hdr.reserved = 0;
    pudp_hdr.protocol = iph->protocol;
    pudp_hdr.len = htons(len);

    ptr = malloc (UDP_PSUEDO_HDR_LEN + len);
    memcpy(ptr, &pudp_hdr, UDP_PSUEDO_HDR_LEN);
    memcpy(ptr + UDP_PSUEDO_HDR_LEN, buf, len);

    csum = checksum((uint16_t *)ptr, UDP_PSUEDO_HDR_LEN + len);
    free (ptr);
    return csum;
}

void ptm_bfd_ses_dump(void)
{
    bfd_session *bfd, *tmp;
    char peer_addr[64], local_addr[64];

    DLOG("Sessions List\n");
    HASH_ITER(sh, session_hash, bfd, tmp) {
        DLOG("session 0x%x with peer %s\n",
             bfd->discrs.my_discr,
             ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr));
    }
    DLOG("Single-hop peers List\n");
    HASH_ITER(ph, peer_hash, bfd, tmp) {
        DLOG("port/peer %s/%s with session 0x%x\n",
             bfd->shop.port_name,
             ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr),
             bfd->discrs.my_discr);
    }
    DLOG("multihop peers List\n");
    HASH_ITER(mh, local_peer_hash, bfd, tmp) {
        DLOG("vrf %s local/peer %s/%s with session 0x%x\n",
             (strlen(bfd->mhop.vrf_name)) ? bfd->mhop.vrf_name : "N/A",
             ptm_ipaddr_net2str(&bfd->mhop.local, local_addr),
             ptm_ipaddr_net2str(&bfd->mhop.peer, peer_addr),
             bfd->discrs.my_discr);
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
    cl_cur_time(timer);
    cl_add_time(timer, tt_epoch);
    /* Update the bfd_tt_epoch, if the timer needs to be fired before the
     * lowest timer */
    if (((bfd_tt_epoch.tv_sec == 0) && (bfd_tt_epoch.tv_nsec == 0)) ||
            (cl_comp_time(&bfd_tt_epoch, timer)) > 0) {
        cl_cp_time(&bfd_tt_epoch, timer);
        ptm_bfd_start_timer(timer);
    }
}

static void ptm_shutdown_bfd(ptm_globals_t *g)
{
    int i;
    for (i = 0; i < BFD_MAX_FD; i++) {
        ptm_fd_cleanup(PTM_MODULE_FD(g, BFD_MODULE, i));
        PTM_MODULE_SET_FD(g, -1, BFD_MODULE, i);
    }

    ptm_bfd_stop_client_timer();
    ptm_bfd_stop_sess_pend_timer();

    PTM_MODULE_SET_STATE(g, BFD_MODULE, MOD_STATE_ERROR);

    /* request a re-init */
    ptm_module_request_reinit();
}

int ptm_init_bfd(ptm_globals_t *g)
{
    int s, flags;
    int mhs;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    int ret;

    ptm_bfd.gbl = g;
    ptm_bfd.session_count = 0;

    /* init the callbacks */
    PTM_MODULE_INITIALIZE(g, BFD_MODULE);
    PTM_MODULE_EVENTCB(g, BFD_MODULE) = ptm_event_bfd;
    PTM_MODULE_POPULATECB(g, BFD_MODULE) = ptm_populate_bfd;
    PTM_MODULE_PROCESSCB(g, BFD_MODULE) = ptm_process_bfd;
    PTM_MODULE_PARSECB(g, BFD_MODULE) = ptm_parse_bfd;
    PTM_MODULE_STATUSCB(g, BFD_MODULE) = ptm_status_bfd;

    /* Initialize BFD global defaults */
    PTM_BFD_SET_GLOBAL_PARM(up_min_tx, BFD_DEFDESIREDMINTX);
    PTM_BFD_SET_GLOBAL_PARM(timers.required_min_rx, BFD_DEFREQUIREDMINRX);
    PTM_BFD_SET_GLOBAL_PARM(timers.required_min_echo, BFD_DEF_REQ_MIN_ECHO);
    PTM_BFD_SET_GLOBAL_PARM(detect_mult, BFD_DEFDETECTMULT);
    PTM_BFD_SET_GLOBAL_PARM(slow_min_tx, BFD_DEF_SLOWTX);
    PTM_BFD_SET_GLOBAL_PARM(mh_ttl, BFD_DEF_MHOP_TTL);
    PTM_BFD_SET_GLOBAL_PARM(afi, BFD_DEF_AFI);
    PTM_BFD_SET_GLOBAL_PARM(send_event, BFD_DEF_SEND_EVT);
    PTM_BFD_SET_GLOBAL_PARM(echo_support, BFD_DEF_ECHO_SUPPORT);

    /* Make UDP socket to receive control packets */
    flags = SOCK_DGRAM | SOCK_CLOEXEC;
    if ((s = socket(PF_INET, flags, IPPROTO_UDP)) < 0) {
        CRITLOG("Can't get receive socket (single-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    /* Add socket to select */
    PTM_MODULE_SET_FD(g, s, BFD_MODULE, BFD_SHOP_FD);

    if (setsockopt(s, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
        CRITLOG("Can't set TTL for outgoing packets (single-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }
    if (setsockopt(s, SOL_IP, IP_RECVTTL, &rcvttl, sizeof(rcvttl)) < 0) {
        CRITLOG("Can't set receive TTL for incoming packets (single-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    if (setsockopt(s, SOL_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo)) < 0) {
        CRITLOG("Can't set receive TTL for incoming packets (single-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(BFD_DEFDESTPORT);
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        CRITLOG("Can't bind socket to default port %d: %m\n",
                        BFD_DEFDESTPORT);
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    ptm_bfd.shop_sock = s;

    /* Make UDP socket to receive multihop control packets */
    flags = SOCK_DGRAM | SOCK_CLOEXEC;
    if ((mhs = socket(PF_INET, flags, IPPROTO_UDP)) < 0) {
        CRITLOG("Can't get receive multi-hop socket: %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    /* Add socket to select */
    PTM_MODULE_SET_FD(g, mhs, BFD_MODULE, BFD_MHOP_FD);

    if (setsockopt(mhs, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
        CRITLOG("Can't set TTL for outgoing packets (multi-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    if (setsockopt(mhs, SOL_IP, IP_RECVTTL, &rcvttl,
                    sizeof(rcvttl)) < 0) {
        CRITLOG("Can't set receive TTL for incoming packets (multi-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    if (setsockopt(mhs, SOL_IP, IP_PKTINFO, &pktinfo,
            sizeof(pktinfo)) < 0) {
        CRITLOG("Can't set receive TTL for incoming packets (multi-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(BFD_DEF_MHOP_DEST_PORT);
    if (bind(mhs, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        CRITLOG("Can't bind socket to default multi-hop port %d: %m\n",
                BFD_DEF_MHOP_DEST_PORT);
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }
    ptm_bfd.mhop_sock = mhs;

    /* Make UDP socket to receive IPv6 control packets */
    flags = SOCK_DGRAM | SOCK_CLOEXEC;
    if ((s = socket(PF_INET6, flags, IPPROTO_UDP)) < 0) {
        CRITLOG("Can't get receive socket (single-hop IPv6): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    /* Add socket to select */
    PTM_MODULE_SET_FD(g, s, BFD_MODULE, BFD_SHOP6_FD);

    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                    &ttlval, sizeof(ttlval)) < 0) {
        CRITLOG("Can't set TTL for outgoing packets (single-hop IPv6): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }
    if (setsockopt(s, IPPROTO_IPV6, IPV6_2292HOPLIMIT,
                        &rcvttl, sizeof(rcvttl)) < 0) {
        CRITLOG("Can't get receive TTL for incoming packets"
                " (single-hop IPv6): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    if (setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTINFO,
                        &ipv6_pktinfo, sizeof(ipv6_pktinfo)) < 0) {
        CRITLOG("Can't set IPv6 receive packet info (single-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                        &ipv6_only, sizeof(ipv6_only)) < 0) {
        CRITLOG("Can't set IPv6 only option (single-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    memset(&sin6, 0, sizeof(struct sockaddr_in6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = htons(BFD_DEFDESTPORT);
    if (bind(s, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
        CRITLOG("Can't bind socket to default port %d: %m\n",
                        BFD_DEFDESTPORT);
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }
    ptm_bfd.shopv6_sock = s;

    /* Make UDP socket to receive multihop IPv6 control packets */
    flags = SOCK_DGRAM | SOCK_CLOEXEC;
    if ((mhs = socket(PF_INET6, flags, IPPROTO_UDP)) < 0) {
        CRITLOG("Can't create receive socket (multi-hop IPv6): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    /* Add socket to select */
    PTM_MODULE_SET_FD(g, mhs, BFD_MODULE, BFD_MHOP6_FD);

    if (setsockopt(mhs, IPPROTO_IPV6, IPV6_2292HOPLIMIT,
                        &rcvttl, sizeof(rcvttl)) < 0) {
        CRITLOG("Can't get receive TTL for incoming packets"
                " (multi-hop IPv6): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    if (setsockopt(mhs, IPPROTO_IPV6, IPV6_2292PKTINFO,
                        &ipv6_pktinfo, sizeof(ipv6_pktinfo)) < 0) {
        CRITLOG("Can't set IPv6 receive packet info (multi-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    if (setsockopt(mhs, IPPROTO_IPV6, IPV6_V6ONLY,
                        &ipv6_only, sizeof(ipv6_only)) < 0) {
        CRITLOG("Can't set IPv6 only option (multi-hop): %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    memset(&sin6, 0, sizeof(struct sockaddr_in6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = htons(BFD_DEF_MHOP_DEST_PORT);
    if (bind(mhs, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
        CRITLOG("Can't bind socket to default port %d: %m\n",
                        BFD_DEFDESTPORT);
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }
    ptm_bfd.mhopv6_sock = mhs;

    if ((ret = ptm_bfd_echo_sock_init()) == -1)
        return -1;

    if ((ret = ptm_bfd_vxlan_sock_init()) == -1)
        return -1;

    PTM_MODULE_SET_STATE(g, BFD_MODULE, MOD_STATE_INITIALIZED);

    return ret;
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
    bfd_sess_parms *tmp_topo, *topo_cfg, *topo_parms;
    int old;
    struct ptm_conf_port *port;

    INFOLOG("%s: Post Init operations \n", __FUNCTION__);

    /* register for peer events */
    PTM_MODULE_PEERCB(ptm_bfd.gbl, BFD_MODULE, NBR_MODULE)
                    = ptm_peer_event_bfd;
    PTM_MODULE_PEERCB(ptm_bfd.gbl, BFD_MODULE, QUAGGA_MODULE)
                    = ptm_peer_event_bfd;
    PTM_MODULE_PEERCB(ptm_bfd.gbl, BFD_MODULE, NETLINK_MODULE)
                    = ptm_peer_event_bfd;

    /* Delete all the old topo configs for port that are not in Topo file*/
    old = HASH_CNT(ph, topo_parm_hash);
    HASH_ITER(ph, topo_parm_hash, topo_cfg, tmp_topo) {
        port = ptm_conf_get_port_by_name(topo_cfg->port_name);
        if (!port || (port && !ptm_conf_is_mod_enabled(port, BFD_MODULE))) {
            /* Delete the Topo cfgs not existing in Topo file */
            INFOLOG("%s: Port %s has been deleted or BFD disabled\n",
                    __FUNCTION__, topo_cfg->port_name);
            HASH_DELETE(ph, topo_parm_hash, topo_cfg);
            free(topo_cfg);
        }
    }

    if (old - HASH_CNT(ph, topo_parm_hash)) {
        INFOLOG("%s: Deleted non-existent ports %d\n", __FUNCTION__,
                old - HASH_CNT(ph, topo_parm_hash));
    }

    old = HASH_CNT(ciph, sess_parm_hash);
    /* validate existing topo based sessions */
    HASH_ITER(ph, peer_hash, bfd, tmp) {
        HASH_FIND(ch, bfd->parm_hash, CLIENT_NAME_DFLT,
                  strlen(CLIENT_NAME_DFLT), topo_parms);

        if (!topo_parms)
            continue;

        HASH_FIND(ph, topo_parm_hash, topo_parms->port_name,
                  strlen(topo_parms->port_name), topo_cfg);

        if (!topo_cfg ||
            (topo_cfg->parms.afi != topo_parms->parms.afi)) {
            handle_bfd_event(NBR_MODULE, topo_parms, EVENT_DEL);
            /* sess parms are deleted by the event handler */
        } else {
            /* update parms */
            handle_bfd_event(NBR_MODULE, topo_cfg, EVENT_UPD);
        }
    }

    if (old - HASH_CNT(ciph, sess_parm_hash)) {
        DLOG("%s: Deleted stale topo sessions %d\n",
             __FUNCTION__, old - HASH_CNT(ph, peer_hash));
    }

    PTM_MODULE_SET_STATE(ptm_bfd.gbl, BFD_MODULE, MOD_STATE_POPULATE);

    return 0;
}


static int
ptm_process_bfd_pkt(int s, ptm_sockevent_e se, void *udata)
{
    int mlen;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    bfd_pkt_t *cp;
    struct cmsghdr *cm;
    bfd_session *bfd;
    uint32_t oldXmtTime;
    uint32_t oldEchoXmt_TO;
    uint32_t ttlval = BFD_TTL_VAL;
    uint8_t old_state;
    struct in_pktinfo *pi = NULL;
    struct in6_pktinfo *pi6 = NULL;
    bool is_mhop = false;
    bool is_vxlan = false;
    ptm_ipaddr peer, local;
    char peer_addr[64];
    int local_ifindex = 0;
    bool echo_support = FALSE;
    char local_portname[MAXNAMELEN+1] = {0};
    bfd_session_vxlan_info_t vxlan_info;
    uint8_t rx_pkt[BFD_RX_BUF_LEN];
    bfd_sess_parms *topo_parms;
    char vrf_name[MAXNAMELEN+1] = {0};

    if (PTM_GET_STATE(ptm_bfd.gbl) != PTM_RUNNING) {
        return (-1);
    }

    if ((s == ptm_bfd.mhop_sock) || (s == ptm_bfd.mhopv6_sock )) {
        is_mhop = true;
    } else if (s == ptm_bfd.echo_sock) {
        return (ptm_bfd_process_echo_pkt(s, se, udata));
    }

    memset(&sin, 0, sizeof(sin));
    memset(&local, 0, sizeof(ptm_ipaddr));
    memset(&peer, 0, sizeof(ptm_ipaddr));
    if ((s == ptm_bfd.mhop_sock) || (s == ptm_bfd.shop_sock)) {
        if ((mlen = recvmsg(s, &msghdr, MSG_DONTWAIT)) < 0) {
            if (errno != EAGAIN) {
                ERRLOG("Error receiving from BFD socket: %m\n");
            }
            return -1;
        }

        /* Get source address */
        sin = *((struct sockaddr_in *)(msghdr.msg_name));

        /* keep in network-byte order */
        peer.ip4_addr.s_addr = sin.sin_addr.s_addr;
        peer.family = AF_INET;
        strcpy(peer_addr, inet_ntoa(sin.sin_addr));

        /* Get and check TTL */
        for (cm = CMSG_FIRSTHDR(&msghdr); cm != NULL;
                cm = CMSG_NXTHDR(&msghdr, cm)) {
            if (cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_TTL) {
                //ttlval = *(uint32_t *)CMSG_DATA(cm);
                memcpy(&ttlval, CMSG_DATA(cm), 4);
                if ((is_mhop == false) && (ttlval != BFD_TTL_VAL)) {
                    INFOLOG("Received pkt with invalid TTL %u from %s flags: %d\n",
                            ttlval, peer_addr, msghdr.msg_flags);
                    return -1;
                }
            } else if (cm->cmsg_level == SOL_IP &&
                        cm->cmsg_type == IP_PKTINFO) {
                pi = (struct in_pktinfo *)CMSG_DATA(cm);
                if (pi) {
                    /* keep in network-byte order */
                    local.family = AF_INET;
                    local.ip4_addr.s_addr = pi->ipi_addr.s_addr;
                    local_ifindex = pi->ipi_ifindex;
                    _fetch_portname_from_ifindex(local_ifindex, s,
                                                 local_portname);
                }
            }
        }

        /* Implement RFC 5880 6.8.6 */
        if (mlen < BFD_PKT_LEN) {
            INFOLOG("Received short packet from %s\n", peer_addr);
            return -1;
        }

        cp = (bfd_pkt_t *)(msghdr.msg_iov->iov_base);
    } else if ((s == ptm_bfd.mhopv6_sock) || (s == ptm_bfd.shopv6_sock)) {
        if ((mlen = recvmsg(s, &msghdr6, MSG_DONTWAIT)) < 0) {
            if (errno != EAGAIN) {
                ERRLOG("Error receiving from BFD socket: %m\n");
            }
            return -1;
        }

        /* Get source address */
        sin6 = *((struct sockaddr_in6 *)(msghdr6.msg_name));

        /* keep in network-byte order */
        peer.ip6_addr = sin6.sin6_addr;
        peer.family = AF_INET6;
        inet_ntop (AF_INET6, &sin6.sin6_addr, peer_addr, INET6_ADDRSTRLEN);

        /* Get and check TTL */
        for (cm = CMSG_FIRSTHDR(&msghdr6); cm != NULL;
                cm = CMSG_NXTHDR(&msghdr6, cm)) {
            if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_2292HOPLIMIT) {
                //ttlval = *(uint32_t *)CMSG_DATA(cm);
                memcpy(&ttlval, CMSG_DATA(cm), 4);
                if ((is_mhop == false) && (ttlval != BFD_TTL_VAL)) {
                    INFOLOG("Received pkt with invalid TTL %u from %s flags: %d\n",
                            ttlval, peer_addr, msghdr6.msg_flags);
                    return -1;
                }
            } else if (cm->cmsg_level == IPPROTO_IPV6 &&
                        cm->cmsg_type == IPV6_2292PKTINFO) {
                pi6 = (struct in6_pktinfo *)CMSG_DATA(cm);
                if (pi6) {
                    /* keep in network-byte order */
                    local.family = AF_INET6;
                    ptm_util_extract_ipv6_pkt_info(pi6, &local_ifindex,
                                                    &local.ip6_addr);
                    _fetch_portname_from_ifindex(local_ifindex, s,
                                                 local_portname);
                }
            }
        }

        /* Implement RFC 5880 6.8.6 */
        if (mlen < BFD_PKT_LEN) {
            INFOLOG("Received short packet from %s\n", peer_addr);
            return -1;
        }

        cp = (bfd_pkt_t *)(msghdr6.msg_iov->iov_base);
    } else {
        cp = ptm_bfd_process_vxlan_pkt(s, se, udata, &local_ifindex,
                                        &sin, &vxlan_info, rx_pkt, &mlen);
        if (!cp) {
            return -1;
        }
        is_vxlan = true;
        /* keep in network-byte order */
        peer.ip4_addr.s_addr = sin.sin_addr.s_addr;
        peer.family = AF_INET;
        strcpy(peer_addr, inet_ntoa(sin.sin_addr));
    }

    if (BFD_GETVER(cp->diag) != BFD_VERSION) {
        INFOLOG("Received bad version %d from %s\n",
                BFD_GETVER(cp->diag), peer_addr);
        return -1;
    }

    if (cp->detect_mult == 0) {
        INFOLOG("Detect Mult is zero in pkt from %s\n", peer_addr)
        return -1;
    }

    if ((cp->len < BFD_PKT_LEN) || (cp->len > mlen)) {
        INFOLOG("Invalid length %d in control pkt from %s\n",
                cp->len, peer_addr);
        return -1;
    }

    if (cp->discrs.my_discr == 0) {
        INFOLOG("My discriminator is zero in pkt from %s\n", peer_addr);
        return -1;
    }

    if ((bfd = ptm_bfd_sess_find(cp, local_portname,
                         peer, local, vrf_name, is_mhop)) == NULL) {
        DLOG("Failed to generate session from remote packet\n");
        return -1;
    }

    if (is_vxlan && !ptm_bfd_validate_vxlan_pkt(bfd, &vxlan_info)) {
        return -1;
    }

    bfd->stats.rx_ctrl_pkt++;
    if (is_mhop) {
        if ((BFD_TTL_VAL - bfd->mh_ttl) > ttlval) {
            DLOG("Exceeded max hop count of %d, dropped pkt from"
                    " %s with TTL %d\n",
                    bfd->mh_ttl, inet_ntoa(sin.sin_addr), ttlval);
            return -1;
        }
    } else if (bfd->local_ip.family == AF_UNSPEC) {
        bfd->local_ip = local;
    }

    if ((bfd->discrs.remote_discr != 0) &&
        (bfd->discrs.remote_discr != ntohl(cp->discrs.my_discr))) {
        DLOG("My Discriminator mismatch in pkt"
             "from %s, Expected %d Got %d\n",
             inet_ntoa(sin.sin_addr), bfd->discrs.remote_discr,
             ntohl(cp->discrs.my_discr));
    }

    bfd->discrs.remote_discr = ntohl(cp->discrs.my_discr);
    bfd->remote_ses_state = bfd->ses_state;
    bfd->remote_demand_mode = bfd->demand_mode;

    HASH_FIND(ch, bfd->parm_hash, CLIENT_NAME_DFLT,
              strlen(CLIENT_NAME_DFLT), topo_parms);

    if (topo_parms) {
        echo_support = topo_parms->parms.echo_support;
    }

    /* If received the Final bit, the new values should take effect */
    if (bfd->polling && BFD_GETFBIT(cp->flags)) {
        bfd->timers.desired_min_tx = bfd->new_timers.desired_min_tx;
        bfd->timers.required_min_rx = bfd->new_timers.required_min_rx;
        bfd->new_timers.desired_min_tx = 0;
        bfd->new_timers.required_min_rx = 0;
        bfd->polling = 0;
    }

    if (!bfd->demand_mode) {
        /* Compute detect time */
        bfd->detect_TO =
            cp->detect_mult *
            ((bfd->timers.required_min_rx > ntohl(cp->timers.desired_min_tx)) ?
             bfd->timers.required_min_rx : ntohl(cp->timers.desired_min_tx));
        bfd->detect_TO *= NSEC_PER_USEC;
        bfd->remote_detect_mult = cp->detect_mult;
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
            } /* INIT and UP stays in UP state */
            break;
        }
    }

    if (old_state != bfd->ses_state) {
        DLOG("BFD Sess %d [%s] Old State [%s] : New State [%s]\n",
              bfd->discrs.my_discr, peer_addr,
              state_list[old_state].str,
              state_list[bfd->ses_state].str);
    }
//            INFOLOG("Unexpected packet on session 0x%x with peer %s\n",
//                    bfd->discrs.my_discr, inet_ntoa(bfd->shop.peer));
//            ptm_dump_bfd_pkt(cp);

    if (echo_support) {
        if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
            if (!ntohl(cp->timers.required_min_echo)) {
                ptm_bfd_echo_stop(bfd, 1);
            } else {
                oldEchoXmt_TO = bfd->echo_xmt_TO;
                bfd->echo_xmt_TO = bfd->timers.required_min_echo;
                if (ntohl(cp->timers.required_min_echo) > bfd->echo_xmt_TO)
                    bfd->echo_xmt_TO = ntohl(cp->timers.required_min_echo);
                bfd->echo_xmt_TO *= NSEC_PER_USEC;
                if (oldEchoXmt_TO != bfd->echo_xmt_TO)
                    ptm_bfd_echo_start(bfd);
            }
        } else if (ntohl(cp->timers.required_min_echo)) {
            bfd->echo_xmt_TO = bfd->timers.required_min_echo;
            if (ntohl(cp->timers.required_min_echo) > bfd->echo_xmt_TO)
                bfd->echo_xmt_TO = ntohl(cp->timers.required_min_echo);
            bfd->echo_xmt_TO *= NSEC_PER_USEC;
            ptm_bfd_echo_start(bfd);
        }
    }

    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {

        if (!ntohl(cp->timers.required_min_echo)) {
        }
        bfd->echo_xmt_TO = bfd->timers.required_min_echo;
        if (ntohl(cp->timers.required_min_echo) > bfd->echo_xmt_TO)
            bfd->echo_xmt_TO = ntohl(cp->timers.required_min_echo);
        bfd->echo_xmt_TO *= NSEC_PER_USEC;
    }

    /* Calculate new transmit time */
    oldXmtTime = bfd->xmt_TO;
    bfd->xmt_TO =
        (bfd->timers.desired_min_tx > ntohl(cp->timers.required_min_rx)) ?
        bfd->timers.desired_min_tx : ntohl(cp->timers.required_min_rx);
    bfd->xmt_TO *= NSEC_PER_USEC;

    /* If transmit time has changed, and too much time until next xmt,
     * restart
     */
    if (BFD_GETPBIT(cp->flags)) {
        ptm_bfd_xmt_TO(bfd, 1);
    } else if (oldXmtTime != bfd->xmt_TO) {
        /* XXX add some skid to this as well */
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

static int
ptm_process_bfd(int s, ptm_sockevent_e se, void *udata)
{
    int count = 0;
    int rval;

    while (count++ < 16) {
        rval = ptm_process_bfd_pkt(s, se, udata);

        if (rval)
            break;
    }

    return 0;
}

void ptm_bfd_detect_TO(bfd_session *bfd)
{
    uint8_t old_state;
    char peer_addr[INET6_ADDRSTRLEN];

    old_state = bfd->ses_state;

    switch (bfd->ses_state) {
    case PTM_BFD_UP:
    case PTM_BFD_INIT:
        DLOG("%s Detect timeout on session 0x%x with peer %s,"
             " in state %d\n", __FUNCTION__, bfd->discrs.my_discr,
             ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr),
             bfd->ses_state);
        ptm_bfd_ses_dn(bfd, BFD_DIAGDETECTTIME);
        /* Session down, restart detect timer so we can clean up later */
        bfd_update_timer(&bfd->detect_timer, bfd->detect_TO);
        break;
    default:
        /* Second detect time expiration, zero remote discr (section 6.5.1) */
        bfd->discrs.remote_discr = 0;
        break;
    }

    if (old_state != bfd->ses_state) {
        DLOG("BFD Sess %d [%s] Old State [%s] : New State [%s]\n",
              bfd->discrs.my_discr,
              ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr),
              state_list[old_state].str,
              state_list[bfd->ses_state].str);
    }
}

void _signal_event(bfd_session *bfd,  ptm_event_e type)
{
    char peer_addr[INET6_ADDRSTRLEN+1];

    ptm_event_cleanup(&ptm_bfd.event);
    ptm_bfd.event.module = BFD_MODULE;

    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH))
        ptm_ipaddr_net2str(&bfd->mhop.peer, peer_addr);
    else {
        ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr);
        ptm_bfd.event.liface = strdup(bfd->shop.port_name);
    }

    if (ptm_ipaddr_get_ip_type(peer_addr) == AF_INET)
        ptm_bfd.event.rv4addr = strdup(peer_addr);
    else
        ptm_bfd.event.rv6addr = strdup(peer_addr);

    ptm_bfd.event.type = type;
    ptm_bfd.event.ctxt = bfd;
    ptm_module_handle_event_cb(&ptm_bfd.event);
    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE))
        BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_IGNORE);
}

void ptm_bfd_ses_dn(bfd_session *bfd, uint8_t diag)
{
    char peer_addr[INET6_ADDRSTRLEN];
    int old_state = bfd->ses_state;

    bfd->local_diag = diag;
    bfd->discrs.remote_discr = 0;
    bfd->ses_state = PTM_BFD_DOWN;
    bfd->polling = 0;
    bfd->curr_poll_seq = 0;
    bfd->demand_mode = 0;

    ptm_bfd_snd(bfd, 0);

    cl_clear_time(&bfd->up_time);

    /* only signal clients when going from up->down state */
    if (old_state == PTM_BFD_UP)
        _signal_event(bfd, EVENT_DEL);

    INFOLOG("Session 0x%x down peer %s Rsn %s prev st %s\n",
            bfd->discrs.my_discr,
            ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr),
            get_diag_str(bfd->local_diag),
            state_list[old_state].str);

    /* Stop echo packet transmission if they are active */
    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
        ptm_bfd_echo_stop(bfd, 0);
    }
}

void ptm_bfd_ses_up(bfd_session *bfd)
{
    char peer_addr[INET6_ADDRSTRLEN];

    bfd->local_diag = 0;
    bfd->ses_state = PTM_BFD_UP;
    bfd->polling = 1;

    /* If the peer is capable to receiving Echo pkts */
    if (bfd->echo_xmt_TO && !BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH)) {
        ptm_bfd_echo_start(bfd);
    } else {
        bfd->new_timers.desired_min_tx = bfd->up_min_tx;
        bfd->new_timers.required_min_rx = bfd->timers.required_min_rx;
        ptm_bfd_snd(bfd, 0);
    }

    cl_cur_time(&bfd->up_time);

    _signal_event(bfd, EVENT_ADD);

    INFOLOG("Session 0x%x up peer %s\n", bfd->discrs.my_discr,
            ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr));
}

static bfd_session *
ptm_bfd_sess_find(bfd_pkt_t *cp,
                 char *port_name,
                 ptm_ipaddr peer,
                 ptm_ipaddr local,
                 char *vrf_name,
                 bool is_mhop)
{
    bfd_session     *l_bfd = NULL;
    bfd_mhop_key    mhop;
    bfd_shop_key    shop;
    char peer_addr[64];
    char local_addr[64];
    char vrf_name_buf[MAXNAMELEN + 1];

    /* peer, local are in network-byte order */
    ptm_ipaddr_net2str(&peer, peer_addr);
    ptm_ipaddr_net2str(&local, local_addr);

    if (cp) {
        if (cp->discrs.remote_discr) {
            uint32_t ldisc = ntohl(cp->discrs.remote_discr);
            /* Your discriminator not zero - use it to find session */
            HASH_FIND(sh, session_hash, &ldisc, sizeof(int), l_bfd);

            /* make sure the peer addr matches. sometimes bfd packets
             * with stale disc can still arrive
             */
            if (l_bfd &&
                (l_bfd->discrs.my_discr == ldisc) &&
                (!memcmp(&peer, &l_bfd->shop.peer, sizeof(peer)))) {
                return(l_bfd);
            }
            DLOG("Can't find session for yourDisc 0x%x from %s\n",
                 ldisc, peer_addr);
        } else if (BFD_GETSTATE(cp->flags) == PTM_BFD_DOWN ||
                   BFD_GETSTATE(cp->flags) == PTM_BFD_ADM_DOWN) {

            if (is_mhop) {
                memset((void *)&mhop, 0, sizeof(bfd_mhop_key));
                mhop.peer = peer;
                mhop.local = local;
                if (vrf_name && strlen(vrf_name)) {
                    strcpy(mhop.vrf_name, vrf_name);
                } else if (port_name) {
                    memset(vrf_name_buf, 0, sizeof(vrf_name_buf));
                    if (ptm_bfd_get_vrf_name(port_name, vrf_name_buf) != -1) {
                        strcpy(mhop.vrf_name, vrf_name_buf);
                    }
                }

                /* Your discriminator zero -
                 *     use peer address and local address to find session */
                HASH_FIND(mh, local_peer_hash, &mhop, sizeof(mhop), l_bfd);
            } else {
                memset((void *)&shop, 0, sizeof(bfd_shop_key));
                shop.peer = peer;
                if (strlen(port_name))
                    strcpy(shop.port_name, port_name);
                /* Your discriminator zero -
                 *      use peer address and port to find session */
                HASH_FIND(ph, peer_hash, &shop, sizeof(shop), l_bfd);
            }
            if (l_bfd) {
                /* XXX maybe remoteDiscr should be checked for remoteHeard cases */
                return(l_bfd);
            }
        }
        if (is_mhop)
           DLOG("Can't find multi hop session peer/local %s/%s in vrf %s port %s\n",
                peer_addr, local_addr,
                strlen(mhop.vrf_name)? mhop.vrf_name:"N/A",
                port_name?port_name:"N/A");
        else
           DLOG("Can't find single hop session for peer/port %s/%s\n",
                            peer_addr, port_name);
    } else if (peer.ip4_addr.s_addr ||
               !IN6_IS_ADDR_UNSPECIFIED(&peer.ip6_addr)) {

        if (is_mhop) {
            memset((void *)&mhop, 0, sizeof(bfd_mhop_key));
            mhop.peer = peer;
            mhop.local = local;
            if (vrf_name && strlen(vrf_name))
                strcpy(mhop.vrf_name, vrf_name);

            HASH_FIND(mh, local_peer_hash, &mhop,
                      sizeof(mhop), l_bfd);
        } else {
            memset((void *)&shop, 0, sizeof(bfd_shop_key));
            shop.peer = peer;
            if (strlen(port_name)) {
                strcpy(shop.port_name, port_name);
            }

            HASH_FIND(ph, peer_hash, &shop, sizeof(shop), l_bfd);
        }

        if (l_bfd) {
            /* XXX maybe remoteDiscr should be checked for remoteHeard cases */
            return(l_bfd);
        }

        DLOG("Can't find session for peer %s\n", peer_addr);
    }

    return(NULL);
}

void ptm_bfd_snd(bfd_session *bfd, int fbit)
{
    bfd_pkt_t cp;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;

    /* if the BFD session is for VxLAN tunnel, then construct and
     * send bfd raw packet */
    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_VXLAN)) {
        ptm_bfd_vxlan_pkt_snd(bfd, fbit);
        return;
    }

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
    if (bfd->polling) {
        cp.timers.desired_min_tx = htonl(bfd->new_timers.desired_min_tx);
        cp.timers.required_min_rx = htonl(bfd->new_timers.required_min_rx);
    } else {
        cp.timers.desired_min_tx = htonl(bfd->timers.desired_min_tx);
        cp.timers.required_min_rx = htonl(bfd->timers.required_min_rx);
    }
    cp.timers.required_min_echo = htonl(bfd->timers.required_min_echo);
    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6)) {
        memset(&sin6, 0, sizeof(struct sockaddr_in6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = bfd->shop.peer.ip6_addr;
        if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH)) {
           sin6.sin6_port = htons(BFD_DEF_MHOP_DEST_PORT);
        } else {
           sin6.sin6_port = htons(BFD_DEFDESTPORT);
        }

        if (sendto(bfd->sock, &cp, BFD_PKT_LEN, 0, (struct sockaddr *)&sin6,
                   sizeof(struct sockaddr_in6)) < 0) {
            ERRLOG("Error sending IPv6 control pkt: %m\n");
        } else {
            bfd->stats.tx_ctrl_pkt++;
        }
    } else {
        sin.sin_family = AF_INET;
        sin.sin_addr = bfd->shop.peer.ip4_addr;
        if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH)) {
           sin.sin_port = htons(BFD_DEF_MHOP_DEST_PORT);
        } else {
           sin.sin_port = htons(BFD_DEFDESTPORT);
        }

        if (sendto(bfd->sock, &cp, BFD_PKT_LEN, 0, (struct sockaddr *)&sin,
                   sizeof(struct sockaddr_in)) < 0) {
            ERRLOG("Error sending control pkt: %m\n");
        } else {
            bfd->stats.tx_ctrl_pkt++;
        }
    }
}

static void
ptm_bfd_client_action(bfd_session *bfd, bool up)
{
    char *cmd;
    char *msgbuf;
    char peer_addr[INET6_ADDRSTRLEN];
    bfd_status_ctxt_t b_ctxt = {0};

    if (!up && (bfd->local_diag == BFD_DIAGADMINDOWN)) {
        DLOG("BFD session [%s] Admin down event not sent to clients\n",
                    ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr));
        return;
    }

    if ((cmd = malloc(CMD_SZ)) == NULL)
        return;
    if ((msgbuf = malloc(CTL_MSG_SZ)) == NULL)
        return;
    b_ctxt.bfd = bfd;
    b_ctxt.set_env_var = 1;
    ptm_conf_notify_status_all_clients(&b_ctxt, msgbuf, CTL_MSG_SZ, BFD_MODULE);
    sprintf(cmd, "%s/%s &", ptm_conf_get_conf_dir(),
            (up)? PTM_BFD_SESS_UP_FILE:PTM_BFD_SESS_DOWN_FILE);
    system(cmd);

    free(msgbuf);
    free(cmd);
}

static int
ptm_event_bfd(ptm_event_t *event)
{
    ptm_status_ctxt_t p_ctxt = {0};
    bfd_sess_parms *topo_parms = NULL;
    struct ptm_conf_port *port, tmp_port;
    bfd_session *bfd;
    char peer_addr[INET6_ADDRSTRLEN];

    bfd = event->ctxt;

    if (event->rv4addr) {
        strcpy(peer_addr, event->rv4addr);
    } else if (event->rv6addr) {
        strcpy(peer_addr, event->rv6addr);
    } else {
        ERRLOG("BFD [%s] - no dst ip!\n", ptm_event_type_str(event->type));
        return 0;
    }

    /* look for topo sess parms */
    HASH_FIND(ch, bfd->parm_hash, CLIENT_NAME_DFLT,
              strlen(CLIENT_NAME_DFLT), topo_parms);

    if (topo_parms) {
        port = ptm_conf_get_port(event);
        if (!port) {
            strcpy(tmp_port.port_name, event->liface);
            tmp_port.topo_oper_state = PTM_TOPO_STATE_FAIL;
            port = &tmp_port;
        }
        DLOG("BFD session %s remote IP [%s] ifname [%s] - topo-action\n",
             ptm_event_type_str(event->type), peer_addr,
             event->liface);
        p_ctxt.port = port;
        p_ctxt.bfd_get_next = FALSE;
        strcpy(p_ctxt.bfd_peer, peer_addr);
        p_ctxt.set_env_var = 1;
        ptm_conf_topo_action(&p_ctxt, (event->type == EVENT_ADD));
    }

    /* notify clients of bfd event */
    DLOG("BFD session %s remote IP [%s] - bfd-client-action\n",
         ptm_event_type_str(event->type), peer_addr);
    ptm_bfd_client_action(bfd, (event->type == EVENT_ADD));

    return 0;
}

ptm_event_t *
_cache_event(ptm_event_t *orig)
{
    ptm_event_t *ev = NULL;

    ev = ptm_event_clone(orig);
    if (ev)
        ev->module = BFD_MODULE;
    return ev;
}

#define UPDATE_FIELD(field) {           \
        if (parms->field != 0) {        \
            change = TRUE;              \
            bfd->field = parms->field;  \
        }                               \
    }

static void
_update_vxlan_sess_parms(bfd_session *bfd, bfd_sess_parms *sess_parms)
{
    bfd_session_vxlan_info_t *vxlan_info = &bfd->vxlan_info;
    bfd_parms_list *parms = &sess_parms->parms;

    vxlan_info->vnid = parms->vnid;
    vxlan_info->check_tnl_key = parms->check_tnl_key;
    vxlan_info->forwarding_if_rx = parms->forwarding_if_rx;
    vxlan_info->cpath_down = parms->cpath_down;
    vxlan_info->decay_min_rx = parms->decay_min_rx;

    inet_aton(parms->local_dst_ip, &vxlan_info->local_dst_ip);
    inet_aton(parms->remote_dst_ip, &vxlan_info->peer_dst_ip);

    memcpy(vxlan_info->local_dst_mac, parms->local_dst_mac, ETH_ALEN);
    memcpy(vxlan_info->peer_dst_mac, parms->remote_dst_mac, ETH_ALEN);

    /* The interface may change for Vxlan BFD sessions, so update
     * the local mac and ifindex */
    bfd->ifindex = sess_parms->ifindex;
    memcpy(bfd->local_mac, sess_parms->local_mac, sizeof(bfd->local_mac));
}

static bool
_update_topo_sess_parms(bfd_session *bfd, bool *ret_changed)
{
    bfd_sess_parms *sess_parms;
    bfd_parms_list *parms;
    bool change = FALSE;

    HASH_FIND(ch, bfd->parm_hash, CLIENT_NAME_DFLT,
              strlen(CLIENT_NAME_DFLT), sess_parms);

    if (!sess_parms) {
        /* no topo based sess params */
        return FALSE;
    }

    parms = &sess_parms->parms;

    if (bfd->timers.required_min_rx != parms->timers.required_min_rx)
        UPDATE_FIELD(timers.required_min_rx);
    if (bfd->up_min_tx != parms->up_min_tx)
        UPDATE_FIELD(up_min_tx);
    if (bfd->detect_mult != parms->detect_mult)
        UPDATE_FIELD(detect_mult);
    if (bfd->slow_min_tx != parms->slow_min_tx)
        UPDATE_FIELD(slow_min_tx);

    if (parms->echo_support &&
        !BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6)) {

        if (bfd->timers.required_min_echo != parms->timers.required_min_echo)
            UPDATE_FIELD(timers.required_min_echo);

        if (!BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
            change = TRUE;
            bfd->echo_xmt_TO = bfd->timers.required_min_echo;
            bfd->echo_xmt_TO *= NSEC_PER_USEC;
            ptm_bfd_echo_start(bfd);
        }

    } else {
        uint32_t old = bfd->timers.required_min_echo;
        bfd->timers.required_min_echo = 0;
        if (old != bfd->timers.required_min_echo)
            change = TRUE;
        bfd->stats.tx_echo_pkt = 0;
        bfd->stats.rx_echo_pkt = 0;

        if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
            change = TRUE;
            ptm_bfd_echo_stop(bfd, 1);
        }
    }

    *ret_changed = change;

    return TRUE;
}

static void
ptm_bfd_update_sess_params(bfd_session *bfd)
{
    bfd_sess_parms *sess_parms, *tmp;
    bool change = FALSE;
    bool send_event = FALSE;
    bool topo_present = FALSE;

    /* topo sess params over-ride everything else */
    if (_update_topo_sess_parms(bfd, &change)) {
        topo_present = TRUE;
    }

    /* walk the list of sess parms */
    HASH_ITER(ch, bfd->parm_hash, sess_parms, tmp) {
        bfd_parms_list *parms = &sess_parms->parms;

        if (parms->send_event)
            send_event = TRUE;

        if (topo_present)
            continue;

        if (bfd->timers.required_min_rx < parms->timers.required_min_rx)
            UPDATE_FIELD(timers.required_min_rx);
        if (bfd->up_min_tx < parms->up_min_tx)
            UPDATE_FIELD(up_min_tx);
        if (bfd->detect_mult < parms->detect_mult)
            UPDATE_FIELD(detect_mult);
        if (bfd->slow_min_tx < parms->slow_min_tx)
            UPDATE_FIELD(slow_min_tx);
        if (bfd->mh_ttl < parms->mh_ttl)
            UPDATE_FIELD(mh_ttl);

        if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_VXLAN))
            _update_vxlan_sess_parms(bfd, sess_parms);

    } /* end sess parm loop */

    if (send_event &&
        !BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE)) {
        bfd->send_evt_TO = (bfd->detect_mult *
                            bfd->timers.required_min_rx);
        bfd->send_evt_TO *= NSEC_PER_USEC;
        bfd_update_timer(&bfd->send_evt_timer, bfd->send_evt_TO);
        BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE);
    } else if (!send_event &&
        BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE)) {
        BFD_UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE);
    }

    if (change && (bfd->ses_state == PTM_BFD_UP)) {
        bfd->new_timers.required_min_rx = bfd->timers.required_min_rx;
        bfd->new_timers.desired_min_tx = bfd->up_min_tx;
        bfd->polling = 1;
    }
}

static bfd_sess_parms *
ptm_bfd_init_nbr_parms(ptm_event_t *event, char *peer_addr)
{
    bfd_sess_parms *topo_parms = NULL;
    bfd_sess_parms *curr_topo_parms = NULL;
    bfd_sess_parms *topo_cfg;
    parm_key key;

    /* check if there is a topo param configured */
    HASH_FIND(ph, topo_parm_hash, event->liface,
            strlen(event->liface), topo_cfg);

    if (!topo_cfg)
        return NULL;

    /* run some sanity checks */
    if (!ptm_nbr_is_addr_primary(peer_addr, event->liface)) {
        /* dont allow secondary nbr */
        return NULL;
    }

    if ((event->rv6addr && (topo_cfg->parms.afi == BFD_AFI_V4)) ||
        (event->rv4addr && (topo_cfg->parms.afi == BFD_AFI_V6))) {
        INFOLOG("Ignore Nbr event [%s] - "
                "iface [%s] IP [%s] not supported (AFI mismatch)\n",
                ptm_event_type_str(event->type),
                event->liface, peer_addr);
        return NULL;
    }

    if ((ptm_ipaddr_get_ip_type(peer_addr) == AF_INET6) &&
        !ptm_ipaddr_is_ipv6_link_local(peer_addr)) {
        INFOLOG("Ignore Nbr event [%s] - "
                "iface [%s] IP [%s] not link local\n",
                ptm_event_type_str(event->type),
                event->liface, peer_addr);
        return NULL;
    }

    memset(&key, 0x00, sizeof(key));
    strcpy(key.client_name, CLIENT_NAME_DFLT);
    strcpy(key.port_vrf_name, event->liface);
    strcpy(key.dst_ipaddr, peer_addr);
    HASH_FIND(ciph, sess_parm_hash, &key, sizeof(key), curr_topo_parms);

    if (curr_topo_parms) {
        /* just update the parms - we will apply them later */
        memcpy(&curr_topo_parms->parms, &topo_cfg->parms,
               sizeof(topo_cfg->parms));
        return curr_topo_parms;
    }

    /* check if we have any matching multihop entries */
    for (int i = 0; i < MAX_CLIENTS; i++) {

        ptm_bfd_client_t *cl = _get_client_info_by_idx(i);
        bfd_sess_parms *sp;
        parm_key tkey;

        if (!cl)
            continue;

        memset(&tkey, 0x00, sizeof(tkey));
        strcpy(tkey.client_name, cl->name);
        strcpy(tkey.port_vrf_name, event->liface);
        strcpy(tkey.dst_ipaddr, peer_addr);
        HASH_FIND(ciph, sess_parm_hash, &tkey, sizeof(tkey), sp);

        if (!sp)
            continue;

        if (sp->parms.multi_hop) {
            INFOLOG("Ignore Nbr event [%s] - "
                    "multi-hop sess [%s] exists\n",
                    ptm_event_type_str(event->type),
                    peer_addr);
            return NULL;
        }
    } /* end for all clients */

    /* sanity checks pass */

    /* need to create a new topo sess param */
    topo_parms = ptm_clone_bfd_params(topo_cfg);

    if (!topo_parms)
        return NULL;

    /* update the peer/dst ip */
    strcpy(topo_parms->parms.dst_ipaddr, peer_addr);

    /* update the key for future look up */
    memcpy(&topo_parms->key, &key, sizeof(key));

    /* add the new param */
    HASH_ADD(ciph, sess_parm_hash, key,
             sizeof(topo_parms->key), topo_parms);

    return topo_parms;
}

static void
ptm_bfd_add_sess_params(bfd_session *bfd,
                        bfd_sess_parms *sess_parms)
{
    bfd_sess_parms *tmp;

    HASH_FIND(ch, bfd->parm_hash, sess_parms->client.name,
            strlen(sess_parms->client.name), tmp);
    if (tmp) {
        return;
    }

    _incr_client_num_sessions(sess_parms->client.name, 0);

    HASH_ADD(ch, bfd->parm_hash, client.name,
            strlen(sess_parms->client.name), sess_parms);
}

static void
ptm_handle_nbr_bfd_event(ptm_event_t *event)
{
    ptm_ipaddr peer, local;
    char peer_addr[INET6_ADDRSTRLEN];
    bfd_sess_parms *topo_parms = NULL;
    ptm_bfd_client_t *bfd_client;
    parm_key key;
    bfd_session *bfd = NULL;

    if(!event->rv4addr && !event->rv6addr) {
        /* NULL peer/remote IP passed in - ignore event */
        DLOG("NULL remote IP\n");
        return;
    }

    if (event->rv4addr) {
        ptm_ipaddr_str2net(event->rv4addr, &peer);
        if (event->lv4addr) {
            ptm_ipaddr_str2net(event->lv4addr, &local);
        } else {
            memset(&local, 0, sizeof(ptm_ipaddr));
        }
        strcpy(peer_addr, event->rv4addr);
    } else if (event->rv6addr) {
        ptm_ipaddr_str2net(event->rv6addr, &peer);
        if (event->lv6addr) {
            ptm_ipaddr_str2net(event->lv6addr, &local);
        } else {
            memset(&local, 0, sizeof(ptm_ipaddr));
        }
        strcpy(peer_addr, event->rv6addr);
    }

    if(!event->liface) {
        /* NULL iface passed in - ignore event */
        DLOG("NULL iface for peer %s - ignore event\n", peer_addr);
        return;
    }

    bfd_client = _get_client_info_by_name(CLIENT_NAME_DFLT);

    if (!bfd_client) {
        /* NULL iface passed in - ignore event */
        DLOG("NULL client for peer %s - ignore event\n", peer_addr);
        return;
    }

    /* find the BFD session if it exists */
    bfd = ptm_bfd_sess_find(NULL, event->liface, peer, local, NULL, FALSE);

    switch(event->type) {
        case EVENT_ADD :
        case EVENT_UPD :
            /* if no topo sess params - create one */

            topo_parms = ptm_bfd_init_nbr_parms(event, peer_addr);

            if (!topo_parms) {
                DLOG("Ignore Nbr event [%s] - "
                     "Could not allocate Nbr params [%s:%s]\n",
                     ptm_event_type_str(event->type),
                     event->liface,
                     peer_addr);
                return;
            }

            if (!bfd) {
                bfd = ptm_bfd_sess_new(event, peer, local, FALSE, topo_parms);
                if (!bfd) {
                    /* could not allocate bfd session */
                    ERRLOG("Ignore Nbr event [%s] - "
                           "Could not allocate BFD session [%s:%s]\n",
                           ptm_event_type_str(event->type),
                           event->liface,
                           peer_addr);
                    HASH_DELETE(ciph, sess_parm_hash, topo_parms);
                    free(topo_parms);
                    return;
                }

            } else {
                ptm_bfd_add_sess_params(bfd, topo_parms);
                ptm_bfd_update_sess_params(bfd);
            }

            break;
        case EVENT_DEL :

            /* look for topo sess parms */
            memset(&key, 0x00, sizeof(key));
            strcpy(key.client_name, bfd_client->name);
            strcpy(key.port_vrf_name, event->liface);
            strcpy(key.dst_ipaddr, peer_addr);
            HASH_FIND(ciph, sess_parm_hash, &key, sizeof(key), topo_parms);

            if (!topo_parms) {
                /* no parms exists - nothing to do */
                DLOG("Ignore Nbr event [%s] - "
                     "No topo session params for peer [%s:%s]\n",
                     ptm_event_type_str(event->type),
                     event->liface,
                     peer_addr);
                return;
            }

            if (!bfd) {
                DLOG("Ignore Nbr event [%s] - "
                     "No BFD session peer [%s:%s]\n",
                     ptm_event_type_str(event->type),
                     event->liface,
                     peer_addr);
                return;
            }

            /* remove from bfd parm list */
            HASH_DELETE(ch, bfd->parm_hash, topo_parms);

            if (HASH_CNT(ch, bfd->parm_hash)) {
                ptm_bfd_update_sess_params(bfd);
            } else {
                DLOG("Delete Active bfd session for [%s:%s]\n",
                     event->liface, peer_addr);
                ptm_bfd_ses_dn(bfd, BFD_DIAGADMINDOWN);
                ptm_bfd_ses_del(bfd);
            }

            _decr_client_num_sessions(topo_parms->client.name, 0);
            HASH_DELETE(ciph, sess_parm_hash, topo_parms);
            free(topo_parms);

            break;

        default:
            break;
    }

    return;

}

static void
ptm_handle_internal_bfd_event(ptm_event_t *event)
{
    ptm_ipaddr peer, local;
    char peer_addr[INET6_ADDRSTRLEN];
    char local_portname[MAXNAMELEN+1] = {0};
    ptm_bfd_client_t *bfd_client;
    bfd_sess_parms *sess_parms = NULL, *tmp;
    bool is_mhop;
    parm_key key;
    bfd_session *bfd = NULL;

    if(!event->rv4addr && !event->rv6addr) {
        /* NULL peer/remote IP passed in - ignore event */
        DLOG("NULL remote IP\n");
        return;
    }

    if (event->rv4addr) {
        ptm_ipaddr_str2net(event->rv4addr, &peer);
        if (event->lv4addr) {
            ptm_ipaddr_str2net(event->lv4addr, &local);
        } else {
            memset(&local, 0, sizeof(ptm_ipaddr));
        }
        strcpy(peer_addr, event->rv4addr);
    } else if (event->rv6addr) {
        ptm_ipaddr_str2net(event->rv6addr, &peer);
        if (event->lv6addr) {
            ptm_ipaddr_str2net(event->lv6addr, &local);
        } else {
            memset(&local, 0, sizeof(ptm_ipaddr));
        }
        strcpy(peer_addr, event->rv6addr);
    }

    bfd_client = event->ctxt;
    memset(&key, 0x00, sizeof(key));
    strcpy(key.client_name, bfd_client->name);
    if (event->liface)
        strcpy(key.port_vrf_name, event->liface);
    if (event->vrf_name)
        strcpy(key.port_vrf_name, event->vrf_name);
    strcpy(key.dst_ipaddr, peer_addr);
    HASH_FIND(ciph, sess_parm_hash, &key, sizeof(key), sess_parms);

    if (!sess_parms) {
        /* nothing more to do! */
        INFOLOG("Ignore Int event [%s] - "
                "No sess params Client [%s] session [%s]\n",
                ptm_event_type_str(event->type),
                bfd_client->name, peer_addr);
        return;
    }

    is_mhop = sess_parms->parms.multi_hop;

    if ((!event->vnid_present) && event->liface)
        strcpy(local_portname, event->liface);
    /* find the BFD session if it exists */
    bfd = ptm_bfd_sess_find(NULL, local_portname, peer, local,
                            event->vrf_name, is_mhop);

    switch(event->type) {
        case EVENT_ADD :
        case EVENT_UPD :

            if (!bfd) {
                bfd = ptm_bfd_sess_new(event, peer, local, is_mhop, sess_parms);
                if (!bfd) {
                    /* could not allocate bfd session */
                    ERRLOG("Ignore Int event %s - "
                           "Could not allocate BFD session [%s:%s]\n",
                           ptm_event_type_str(event->type),
                           sess_parms->client.name,
                           peer_addr);
                    return;
                }
            } else {
                ptm_bfd_add_sess_params(bfd, sess_parms);
                ptm_bfd_update_sess_params(bfd);
            }

            break;
        case EVENT_DEL :

            if (!bfd) {
                DLOG("Ignore Int event %s - "
                     "No BFD session peer [%s:%s]\n",
                     ptm_event_type_str(event->type),
                     sess_parms->client.name,
                     peer_addr);
                return;
            }

            HASH_FIND(ch, bfd->parm_hash, bfd_client->name,
                      strlen(bfd_client->name), tmp);
            if (tmp) {
                /* remove existing */
                HASH_DELETE(ch, bfd->parm_hash, tmp);
            }

            if (HASH_CNT(ch, bfd->parm_hash)) {
                ptm_bfd_update_sess_params(bfd);
            } else {
                DLOG("Delete Active bfd session for %s\n", peer_addr);
                ptm_bfd_ses_dn(bfd, BFD_DIAGADMINDOWN);
                ptm_bfd_ses_del(bfd);
            }

            _decr_client_num_sessions(sess_parms->client.name, 0);

            break;

        default:
            break;
    }

    return;
}

static void
bfd_handle_vrf(ptm_event_t *ev)
{
    struct bfd_vrf *vrf, *old_vrf;
    char *str = "ADD";

    HASH_FIND(vh, vrf_hash, &ev->vrf_id, sizeof(ev->vrf_id), old_vrf);

    if (ev->type == EVENT_ADD) {

        vrf = calloc(1, sizeof(*vrf));
        if (!vrf) {
            DLOG ("netlink vrf %s(%u) alloc error %m\n",
                  ev->vrf_name, ev->vrf_id);
            return;
        }
        strcpy(vrf->name, ev->vrf_name);
        vrf->vrf_id = ev->vrf_id;

        if (old_vrf) {
            HASH_DELETE(vh, vrf_hash, old_vrf);
            free(old_vrf);
            str = "UPD";
        }

        DLOG ("%s vrf %s vrf_id %d\n", str, ev->vrf_name, ev->vrf_id);

        HASH_ADD(vh, vrf_hash, vrf_id, sizeof(vrf->vrf_id), vrf);
    } else {
        DLOG ("DEL vrf %s vrf_id %d\n", ev->vrf_name, ev->vrf_id);
        if (old_vrf ) {
            HASH_DELETE(vh, vrf_hash, old_vrf);
            free(old_vrf);
        }
    }
}

static void
bfd_handle_iface (ptm_event_t *ev)
{
    struct bfd_iface *ifnew, *ifold;
    char *str = "ADD";

    HASH_FIND(ifh, iface_hash, ev->liface, strlen(ev->liface), ifold);

    if (ev->type == EVENT_ADD) {

        ifnew = calloc(1, sizeof(struct bfd_iface));
        if (ifnew == NULL) {
            ERRLOG("%s: not enough memory\n", __FUNCTION__);
            return;
        }

        strcpy(ifnew->ifname, ev->liface);
        ifnew->vrf_id = ev->vrf_id;

        if (ifold) {
            HASH_DELETE(ifh, iface_hash, ifold);
            free(ifold);
            str = "UPD";
        }
        DLOG("%s iface %s vrf_id %d\n", str, ev->liface, ev->vrf_id);
        HASH_ADD(ifh, iface_hash, ifname,
                 strlen(ifnew->ifname), ifnew);
    } else {
        if (ifold) {
            DLOG("DEL iface %s vrf %d\n",
                 ifold->ifname, ifold->vrf_id);
            HASH_DELETE(ifh, iface_hash, ifold);
            free(ifold);
        }
    }
}

static void
ptm_handle_nl_bfd_event(ptm_event_t *event)
{
    if(event->rv4addr || event->rv6addr) {
        return;
    }

    if(event->vrf_name && event->vrf_id) {
        bfd_handle_vrf(event);
    } else if (event->liface) {
        bfd_handle_iface (event);
    }
}

static int
ptm_peer_event_bfd(ptm_event_t *event)
{
    char *src_addr = (event->lv4addr) ? event->lv4addr :
                        (event->lv6addr)?event->lv6addr:"N/A";
    char *peer_addr = (event->rv4addr) ? event->rv4addr :
                        (event->rv6addr)?event->rv6addr:"N/A";

    DLOG("Recv [%s] event [%s] vrf [%s] Ifname [%s] Src [%s] Dst [%s] [%s]\n",
         ptm_module_string(event->module),
         ptm_event_type_str (event->type),
         (event->vrf_name)?event->vrf_name:"N/A",
         (event->liface)?event->liface:"N/A",
         src_addr, peer_addr,
         (event->bfdtype == BFD_MULTI_HOP)?"multihop":"singlehop");

    switch(event->module) {
        case NBR_MODULE:
            ptm_handle_nbr_bfd_event(event);
            break;
        case BFD_MODULE:
            ptm_handle_internal_bfd_event(event);
            break;
        case NETLINK_MODULE:
            ptm_handle_nl_bfd_event(event);
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

static bfd_session *
ptm_bfd_sess_new(ptm_event_t *event,
                 ptm_ipaddr peer,
                 ptm_ipaddr local,
                 bool  is_mhop,
                 bfd_sess_parms *sess_parms)
{
    bfd_session *bfd, *l_bfd;
    bfd_mhop_key mhop;
    bfd_shop_key shop;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    int pcount;
    static int srcPort = BFD_SRCPORTINIT;
    char peer_addr[64], local_addr[64];

    strcpy(peer_addr, (event->rv4addr) ? event->rv4addr : event->rv6addr);

    /* check to see if this needs a new session */
    if (is_mhop) {
        memset((void *)&mhop, 0, sizeof(bfd_mhop_key));
        mhop.peer = peer;
        mhop.local = local;
        if (strlen(sess_parms->parms.vrf_name))
            strcpy(mhop.vrf_name, sess_parms->parms.vrf_name);

        HASH_FIND(mh, local_peer_hash, &mhop, sizeof(mhop), l_bfd);
    } else {
        shop.peer = peer;
        memset(shop.port_name, 0x00, sizeof(shop.port_name));
        if (!event->vnid_present && event->liface)
            strcpy(shop.port_name, event->liface);

        HASH_FIND(ph, peer_hash, &shop, sizeof(shop), l_bfd);
    }

    if (l_bfd) {
        DLOG("Duplicate session add event for neigh %s\n", peer_addr);
        return NULL;
    }

    /* Get memory */
    if ((bfd = calloc(1, sizeof(bfd_session))) == NULL) {
        ERRLOG("Can't malloc memory for new session: %m\n");
        return NULL;
    }

    if (event->liface && !is_mhop) {
        bfd->ifindex = sess_parms->ifindex;
        memcpy(bfd->local_mac, sess_parms->local_mac, sizeof(bfd->local_mac));
    }

    if (event->vnid_present) {
        BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_VXLAN);
    }

    /*
     * Get socket for transmitting control packets.  Note that if we
     * could use the destination port (3784) for the source
     * port we wouldn't need a socket per session.
     */
    if (peer.family == AF_INET) {
        if ((bfd->sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            ERRLOG("Can't get socket for new session: %m\n");
            free(bfd);
            return NULL;
        }

        if (!event->vnid_present) {
            /* Set TTL to 255 for all transmitted packets */
            if (setsockopt(bfd->sock, SOL_IP, IP_TTL, &ttlval,
                    sizeof(ttlval)) < 0) {
                ERRLOG("Can't set TTL for new session: %m\n");
                close(bfd->sock);
                free(bfd);
                return NULL;
            }
        }

        /* Set TOS to CS6 for all transmitted packets */
        if (setsockopt(bfd->sock, IPPROTO_IP, IP_TOS, &tosval,
                       sizeof(tosval)) < 0) {
            ERRLOG("Can't set TOS for new session: %m\n");
            close(bfd->sock);
            free(bfd);
            return NULL;
        }

        /* dont bind-to-device incase of vxlan */
        if (!event->vnid_present &&
            event->liface) {
            if (setsockopt(bfd->sock, SOL_SOCKET, SO_BINDTODEVICE,
                            event->liface, strlen(event->liface)+1) < 0) {
                ERRLOG("Can't bind to interface for new session: %m\n");
                close(bfd->sock);
                free(bfd);
                return NULL;
            }
        } else if (is_mhop && strlen(sess_parms->parms.vrf_name)) {
            if (setsockopt(bfd->sock, SOL_SOCKET, SO_BINDTODEVICE,
                            sess_parms->parms.vrf_name,
                            strlen(sess_parms->parms.vrf_name)+1) < 0) {
                ERRLOG("Can't bind to vrf %s for new session: %m\n",
                            sess_parms->parms.vrf_name);
                close(bfd->sock);
                free(bfd);
                return NULL;
            }
        }

        /* Find an available source port in the proper range */
        sin.sin_family = AF_INET;
        if (is_mhop || event->vnid_present) {
           sin.sin_addr = local.ip4_addr;
        } else {
           sin.sin_addr.s_addr = INADDR_ANY;
        }

        pcount = 0;
        do {
            if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
                /* Searched all ports, none available */
                ERRLOG("Can't find source port for new session (%m)\n");
                close(bfd->sock);
                free(bfd);
                return NULL;
            }
            if (srcPort >= BFD_SRCPORTMAX) srcPort = BFD_SRCPORTINIT;
            sin.sin_port = htons(srcPort++);
        } while (bind(bfd->sock, (struct sockaddr *)&sin, sizeof(sin)) < 0);
    } else {
        if ((bfd->sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            ERRLOG("Can't get IPv6 socket for new session: %m\n");
            free(bfd);
            return NULL;
        }

        if (!event->vnid_present) {
            /* Set TTL to 255 for all transmitted packets */
            if (setsockopt(bfd->sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttlval,
                    sizeof(ttlval)) < 0) {
                ERRLOG("Can't set TTL for new session: %m\n");
                close(bfd->sock);
                free(bfd);
                return NULL;
            }
        }
        /* Set TOS to CS6 for all transmitted packets */
        if (setsockopt(bfd->sock, IPPROTO_IPV6, IPV6_TCLASS, &tosval,
                       sizeof(tosval)) < 0) {
            ERRLOG("Can't set TOS for new session: %m\n");
            close(bfd->sock);
            free(bfd);
            return NULL;
        }

        /* Find an available source port in the proper range */
        memset(&sin6, 0, sizeof(struct sockaddr_in6));
        sin6.sin6_family = AF_INET6;
        if (local.family != 0) {
            sin6.sin6_addr = local.ip6_addr;
            if (ptm_ipaddr_is_ipv6_link_local(event->lv6addr))
                sin6.sin6_scope_id = sess_parms->ifindex;
        } else if (event->liface){
           sin6.sin6_scope_id = sess_parms->ifindex;
        }

        if (event->liface) {
            if (setsockopt(bfd->sock, SOL_SOCKET, SO_BINDTODEVICE, event->liface,
                            strlen(event->liface)+1) < 0) {
                ERRLOG("Can't bind to interface for new session: %m\n");
                close(bfd->sock);
                free(bfd);
                return NULL;
            }
        } else if (is_mhop && strlen(sess_parms->parms.vrf_name)) {
            if (setsockopt(bfd->sock, SOL_SOCKET, SO_BINDTODEVICE,
                            sess_parms->parms.vrf_name,
                            strlen(sess_parms->parms.vrf_name)+1) < 0) {
                ERRLOG("Can't bind to vrf %s for new session: %m\n",
                            sess_parms->parms.vrf_name);
                close(bfd->sock);
                free(bfd);
                return NULL;
            }
        }

        pcount = 0;
        do {
            if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
                /* Searched all ports, none available */
                ERRLOG("Can't find source port for new session (%m)\n");
                close(bfd->sock);
                free(bfd);
                return NULL;
            }
            if (srcPort >= BFD_SRCPORTMAX) srcPort = BFD_SRCPORTINIT;
            sin6.sin6_port = htons(srcPort++);
        } while (bind(bfd->sock, (struct sockaddr *)&sin6, sizeof(sin6)) < 0);
    }

    if (peer.family == AF_INET6) {
        BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6);
    }

    /* Initialize the session */
    ptm_bfd_add_sess_params(bfd, sess_parms);
    ptm_bfd_update_sess_params(bfd);

    bfd->ses_state = PTM_BFD_DOWN;
    bfd->discrs.my_discr = ptm_bfd_gen_ID();
    bfd->discrs.remote_discr = 0;
    bfd->local_ip = local;
    bfd->timers.desired_min_tx = bfd->up_min_tx;

    /* Start transmitting with slow interval until peer responds */
    bfd->xmt_TO = (bfd->slow_min_tx * NSEC_PER_USEC);
    cl_cur_time(&bfd->xmt_timer);
    bfd->detect_TO = (bfd->detect_mult * bfd->slow_min_tx * NSEC_PER_USEC);
    bfd_update_timer(&bfd->detect_timer, bfd->detect_TO);

    HASH_ADD(sh, session_hash, discrs.my_discr, sizeof(int), bfd);
    if (is_mhop) {
        BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_MH);
        bfd->timers.required_min_echo = 0;
        bfd->mhop.peer = peer;
        bfd->mhop.local = local;
        if (strlen(sess_parms->parms.vrf_name))
            strcpy(bfd->mhop.vrf_name, sess_parms->parms.vrf_name);
        HASH_ADD(mh, local_peer_hash, mhop, sizeof(bfd->mhop), bfd);
    } else {
        bfd->shop.peer = peer;
        if (!event->vnid_present)
            strcpy(bfd->shop.port_name, event->liface);
        HASH_ADD(ph, peer_hash, shop, sizeof(bfd->shop), bfd);
    }

    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_VXLAN)) {
        memcpy(bfd->peer_mac, bfd_def_vxlan_dmac, ETH_ALEN);
    } else if (event->rmac) {
        sscanf(event->rmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &bfd->peer_mac[0], &bfd->peer_mac[1], &bfd->peer_mac[2],
           &bfd->peer_mac[3], &bfd->peer_mac[4], &bfd->peer_mac[5]);
        DLOG("%s: Assigning remote mac = %s\n",
             __FUNCTION__, event->rmac);
        //memcpy(bfd->peer_mac, event->rmac, ETH_ALEN);
    }

    /* Start transmitting control packets */
    if (ptm_bfd.session_count == 0) {
        /* setup baseline time */
        bfd_tt_epoch.tv_sec = 0;
        bfd_tt_epoch.tv_nsec = 0;
        ptm_bfd.fetch_timer = cl_timer_create();
        ptm_bfd_start_xmt(bfd);
    } else {
        ptm_bfd_xmt_TO(bfd, 0);
    }
    ptm_bfd.session_count ++;

    if (is_mhop) {
        ptm_ipaddr_net2str(&bfd->mhop.peer, peer_addr);
        ptm_ipaddr_net2str(&bfd->mhop.local, local_addr);
        INFOLOG("Created new session 0x%x with vrf %s peer %s local %s\n",
            bfd->discrs.my_discr,
            (strlen(bfd->mhop.vrf_name)) ? bfd->mhop.vrf_name : "N/A",
            peer_addr, local_addr);
    } else {
        INFOLOG("Created new session 0x%x with peer %s port %s\n",
            bfd->discrs.my_discr,
            ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr), event->liface);
    }
    //ptm_bfd_ses_dump();
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

void ptm_bfd_xmt_TO(bfd_session *bfd, int fbit)
{

    /* Send the scheduled control packet */
    ptm_bfd_snd(bfd, fbit);
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

static void
ptm_bfd_ses_del(bfd_session *bfd)
{
    char peer_addr[INET6_ADDRSTRLEN];
    char local_addr[INET6_ADDRSTRLEN];


    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH)) {
        INFOLOG("Deleting session 0x%x with vrf %s peer %s local %s\n",
            bfd->discrs.my_discr,
            (strlen(bfd->mhop.vrf_name)) ? bfd->mhop.vrf_name : "N/A",
            ptm_ipaddr_net2str(&bfd->mhop.peer, peer_addr),
            ptm_ipaddr_net2str(&bfd->mhop.local, local_addr));
        HASH_DELETE(mh, local_peer_hash, bfd);
    } else {
        INFOLOG("Deleting session 0x%x with peer %s port %s\n",
            bfd->discrs.my_discr,
            ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr),
            bfd->shop.port_name);
        HASH_DELETE(ph, peer_hash, bfd);
    }

    HASH_DELETE(sh, session_hash, bfd);

    /* account for timers */
    ptm_bfd.session_count --;
    if (ptm_bfd.session_count == 0) {
        cl_timer_destroy(ptm_bfd.fetch_timer);
        ptm_bfd.fetch_timer = NULL;
    }

    close(bfd->sock);
    free(bfd);

    return;
}

/*
 * This function is the timer loop for bfd events. The actual timer
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
                    ptm_bfd_xmt_TO(bfd, 0);
                }
                if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE) &&
                        cl_comp_time(&cts, &bfd->echo_xmt_timer) >= 0) {
                    ptm_bfd_echo_xmt_TO(bfd);
                }
                if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE) &&
                        cl_comp_time(&cts, &bfd->send_evt_timer) >= 0) {
                    ptm_bfd_send_evt_TO(bfd);
                }
                if (bfd->ses_state == PTM_BFD_INIT ||
                    bfd->ses_state == PTM_BFD_UP) {
                    if (cl_comp_time(&cts, &bfd->detect_timer) >= 0) {
                        ptm_bfd_detect_TO(bfd);
                    }
                    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE) &&
                        (bfd->ses_state == PTM_BFD_UP) &&
                        (cl_comp_time(&cts, &bfd->echo_detect_timer)) >= 0) {
                        ptm_bfd_echo_detect_TO(bfd);
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
                if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE) &&
                    (cl_comp_time(&bfd_tt_epoch, &bfd->echo_xmt_timer) >= 0)) {
                    cl_cp_time(&bfd_tt_epoch, &bfd->echo_xmt_timer);
                }
                if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE) &&
                    (cl_comp_time(&bfd_tt_epoch, &bfd->send_evt_timer) >= 0)) {
                    cl_cp_time(&bfd_tt_epoch, &bfd->send_evt_timer);
                }

                if (bfd->ses_state == PTM_BFD_INIT ||
                    bfd->ses_state == PTM_BFD_UP) {
                    if (cl_comp_time(&bfd_tt_epoch, &bfd->detect_timer) >= 0) {
                        cl_cp_time(&bfd_tt_epoch, &bfd->detect_timer);
                    }
                    if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE) &&
                        (bfd->ses_state == PTM_BFD_UP) &&
                        (cl_comp_time(&bfd_tt_epoch, &bfd->echo_detect_timer)) >= 0) {
                        cl_cp_time(&bfd_tt_epoch, &bfd->echo_detect_timer);
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

static int bfd_parse_detect_mult(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    PTM_BFD_SET_PARM(parms, detect_mult, value);

    DLOG("%s: Assigning detect_mult = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_required_min_rx(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_msec_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, timers.required_min_rx, value);

    DLOG("%s: Assigning required_min_rx = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_up_min_tx(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_msec_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, up_min_tx, value);

    DLOG("%s: Assigning up_min_tx = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_echo_support(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    value = (value)? 1:0;

    PTM_BFD_SET_PARM(parms, echo_support, value);

    DLOG("%s: Assigning echo_support = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_required_min_echo(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_msec_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    if (value < BFD_MIN_REQ_MIN_ECHO) {
        PTM_BFD_SET_PARM(parms, timers.required_min_echo, BFD_MIN_REQ_MIN_ECHO);
    } else {
        PTM_BFD_SET_PARM(parms, timers.required_min_echo, value);
    }

    DLOG("%s: Assigning required_min_echo = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_slow_min_tx(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_msec_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, slow_min_tx, value);

    DLOG("%s: Assigning slow_min_tx = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_src_ipaddr(bfd_parms_list *parms, char *val)
{
    struct in_addr tmp;

    if (inet_aton(val, &tmp) == -1) {
        ERRLOG("%s: Invalid src_ipaddr = %s\n", __FUNCTION__, val);
        return -1;
    }

    /* everything ok */
    PTM_BFD_STRCPY_PARM(parms, src_ipaddr, val);

    DLOG("%s: Assigning src_ipaddr = %s\n", __FUNCTION__, val);
    return 0;
}

static int bfd_parse_dst_ipaddr(bfd_parms_list *parms, char *val)
{
    struct in_addr tmp;

    if (inet_aton(val, &tmp) == -1) {
        ERRLOG("%s: Invalid dst_ipaddr = %s\n", __FUNCTION__, val);
        return -1;
    }

    /* everything ok */
    PTM_BFD_STRCPY_PARM(parms, dst_ipaddr, val);

    DLOG("%s: Assigning dst_ipaddr = %s\n", __FUNCTION__, val);
    return 0;
}

static int bfd_parse_ifname(bfd_parms_list *parms, char *val)
{
    /* everything ok */
    PTM_BFD_STRCPY_PARM(parms, ifname, val);

    DLOG("%s: Assigning ifname = %s\n", __FUNCTION__, val);
    return 0;
}

static int bfd_parse_vnid(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, vnid, value);
    PTM_BFD_SET_PARM(parms, enable_vnid, 1);

    DLOG("%s: Assigning vnid = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_multi_hop(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, multi_hop, value);

    DLOG("%s: Assigning multi_hop = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_local_dst_mac(bfd_parms_list *parms, char *val)
{
    uint8_t mac[6];

    sscanf(val, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    PTM_BFD_MEMCPY_PARM(parms, local_dst_mac, mac);

    DLOG("%s: Assigning local_dst_mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
         __FUNCTION__, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}

static int bfd_parse_local_dst_ip(bfd_parms_list *parms, char *val)
{
    struct in_addr tmp;

    if (inet_aton(val, &tmp) == -1) {
        ERRLOG("%s: Invalid local_dst_ip = %s\n", __FUNCTION__, val);
        return -1;
    }

    /* everything ok */
    PTM_BFD_STRCPY_PARM(parms, local_dst_ip, val);

    DLOG("%s: Assigning local_dst_ip = %s\n", __FUNCTION__, val);
    return 0;
}

static int bfd_parse_remote_dst_mac(bfd_parms_list *parms, char *val)
{
    uint8_t mac[6];

    sscanf(val, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    PTM_BFD_MEMCPY_PARM(parms, remote_dst_mac, mac);
    DLOG("%s: Assigning remote_dst_mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
         __FUNCTION__, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}

static int bfd_parse_remote_dst_ip(bfd_parms_list *parms, char *val)
{
    struct in_addr tmp;

    if (inet_aton(val, &tmp) == -1) {
        ERRLOG("%s: Invalid remote_dst_ip = %s\n", __FUNCTION__, val);
        return -1;
    }

    /* everything ok */
    PTM_BFD_STRCPY_PARM(parms, remote_dst_ip, val);

    DLOG("%s: Assigning remote_dst_ip = %s\n", __FUNCTION__, val);
    return 0;
}

static int bfd_parse_decay_min_rx(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, decay_min_rx, value);

    DLOG("%s: Assigning decay_min_rx = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_forwarding_if_rx(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, forwarding_if_rx, value);

    DLOG("%s: Assigning forwarding_if_rx = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_cpath_down(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, cpath_down, value);

    DLOG("%s: Assigning cpath_down = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_check_tnl_key(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, check_tnl_key, value);

    DLOG("%s: Assigning check_tnl_key = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_max_hop_cnt(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    PTM_BFD_SET_PARM(parms, mh_ttl, value);

    DLOG("%s: Assigning mh_ttl = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_convert_afi_str2int(char *afi)
{
    if (strcasecmp(afi, "v4") == 0)
        return BFD_AFI_V4;
    else if (strcasecmp(afi, "v6") == 0)
        return BFD_AFI_V6;
    else if (strcasecmp(afi, "both") == 0)
        return BFD_AFI_BOTH;
    else
        /* default */
        return BFD_AFI_V4;
}

static int bfd_parse_afi(bfd_parms_list *parms, char *val)
{
    int value;

    value = bfd_convert_afi_str2int(val);

    /* everything ok */
    PTM_BFD_SET_PARM(parms, afi, value);

    DLOG("%s: Assigning afi = %s (%d)\n", __FUNCTION__, val, value);
    return 0;
}

static int bfd_parse_send_event(bfd_parms_list *parms, char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (value < 0)
        return value;

    /* everything ok */
    PTM_BFD_SET_PARM(parms, send_event, value);

    DLOG("%s: Assigning send_event = %d\n", __FUNCTION__, value);
    return 0;
}

static int bfd_parse_vrf_name(bfd_parms_list *parms, char *val)
{
    /* everything ok */
    PTM_BFD_STRCPY_PARM(parms, vrf_name, val);

    DLOG("%s: Assigning vrfName = %s\n", __FUNCTION__, val);
    return 0;
}

static void
ptm_parse_bfd_template(char *args, char *tmpl)
{
    char val[MAXNAMELEN];
    tmpl[0] = '\0';
    ptm_conf_find_key_val(BFD_TEMPLATE_KEY, args, val);
    if (strlen(val)) {
        DLOG("%s: Found template [%s] \n", __FUNCTION__, val);
        ptm_conf_get_template_str(val, tmpl);
    }
    return;
}

static bfd_sess_parms *
ptm_clone_bfd_params(bfd_sess_parms *o)
{
    bfd_sess_parms *d = NULL;

    d = ptm_bfd_alloc_sess_parms();

    if (!d) {
        ERRLOG("%s: Could not init parm entry\n", __FUNCTION__);
        return NULL;
    }

    strcpy(d->port_name, o->port_name);
    d->ifindex = o->ifindex;
    memcpy(d->local_mac, o->local_mac, sizeof(d->local_mac));
    memcpy(&d->parms, &o->parms, sizeof(d->parms));
    memcpy(&d->client, &o->client, sizeof(d->client));
    memcpy(&d->key, &o->key, sizeof(d->key));

    return d;
}

static bfd_sess_parms *
ptm_parse_bfd_params(char *args, void *in_ctxt)
{
    bfd_sess_parms *entry = NULL;
    int i, seqid;
    char in_args[MAX_ARGLEN], tmpl_str[MAX_ARGLEN];
    char val[MAXNAMELEN];

    if (!args && !in_ctxt) {
        ERRLOG("%s: NULL args\n", __FUNCTION__);
        return NULL;
    }

    entry = ptm_bfd_alloc_sess_parms();

    if (!entry) {
        ERRLOG("%s: Could not init parm entry\n", __FUNCTION__);
        return NULL;
    }

    if (args && (!strlen(args) || (strlen(args) >= MAX_ARGLEN)))
        return entry;

    if (args) {
        strcpy(in_args, args);
        /* check if there is a template defined  */
        ptm_parse_bfd_template(in_args, tmpl_str);

        if (strlen(tmpl_str)) {
            DLOG("%s: Allow template [%s]\n", __FUNCTION__, tmpl_str);
            strcpy(in_args, tmpl_str);
        }
    }

    /* check for valid session params */
    for(i = 0; bfd_parms_key_tbl[i].key; i++) {

        if (args)
            ptm_conf_find_key_val(bfd_parms_key_tbl[i].key, in_args, val);
        else
            ptm_lib_find_key_in_msg(in_ctxt, bfd_parms_key_tbl[i].key, val);

        if (strlen(val)) {
            /* found key/val */
            bfd_parms_key_tbl[i].key_cb(&entry->parms, val);
        }
    }

    /* check for some client params */
    if (args)
        ptm_conf_find_key_val(CLIENT_NAME, in_args, val);
    else
        ptm_lib_find_key_in_msg(in_ctxt, CLIENT_NAME, val);

    if (strlen(val)) {
        /* found key/val */
        strcpy(entry->client.name, val);
        DLOG("%s: Assigning client name = %s\n", __FUNCTION__, val);
    }

    if (args)
        ptm_conf_find_key_val(CLIENT_SEQ_ID, in_args, val);
    else
        ptm_lib_find_key_in_msg(in_ctxt, CLIENT_SEQ_ID, val);

    if (strlen(val)) {
        /* found key/val */
        seqid = ptm_conf_parse_ulong_parm(val);
        if (seqid > 0) {
            DLOG("%s: Assigning seqid = %d\n", __FUNCTION__, seqid);
            entry->client.seqid = seqid;
        }
    }

    if (strlen(entry->parms.ifname))
        strcpy(entry->port_name, entry->parms.ifname);

    return entry;
}

static int
ptm_parse_bfd(struct ptm_conf_port *port, char *args)
{
    bfd_sess_parms *topo_cfg;

    DLOG("bfd %s args %s\n", port->port_name,
            (args && strlen(args))?args:"None");

    if (!args)
        return -1;

    if (!_get_client_info_by_name(CLIENT_NAME_DFLT))
        _add_client_info(CLIENT_NAME_DFLT, CLIENT_SEQID_DFLT);

    HASH_FIND(ph, topo_parm_hash, port->port_name,
              strlen(port->port_name), topo_cfg);

    if (topo_cfg) {
        HASH_DELETE(ph, topo_parm_hash, topo_cfg);
        free(topo_cfg);
    }

    topo_cfg = ptm_parse_bfd_params(args, NULL);

    if (!topo_cfg) {
        ERRLOG("%s: Could not allocate topo config %s\n", __FUNCTION__,
               port->port_name);
        return -1;
    }

    strncpy(topo_cfg->port_name, port->port_name, sizeof(port->port_name));
    strncpy(topo_cfg->parms.ifname, port->port_name, sizeof(port->port_name));
    topo_cfg->ifindex = ptm_bfd_fetch_ifindex(port->port_name,
            ptm_bfd.shop_sock);
    ptm_bfd_fetch_local_mac(port->port_name, ptm_bfd.shop_sock,
                            topo_cfg->local_mac);
    HASH_ADD(ph, topo_parm_hash, port_name,
             strlen(port->port_name), topo_cfg);

    return 0;
}

#define PTM_LIB_APPEND_BFD(k, v) \
        ptm_lib_append_msg(ptm_bfd.gbl->ptmlib_hdl, out_ctxt, k, v)

void
ptm_bfd_sess_up_time (struct timespec *last_up_time, char *buf, int len)
{
    struct timespec curr_time;
    struct timespec up_time;
    struct tm tm;

    if ((last_up_time->tv_sec == 0) && (last_up_time->tv_nsec == 0))
    {
        snprintf (buf, len, "N/A");
        return;
    }

    cl_cur_time(&curr_time);
    cl_diff_time_ts(&curr_time, last_up_time, &up_time);
    gmtime_r (&up_time.tv_sec, &tm);

    snprintf (buf, len, "%d:%02d:%02d:%02d",
                tm.tm_yday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

#define UPDATE_ENV_VAR(s, v) {  \
            if (strlen(v)) setenv(s, v, 1); \
            else setenv(s, "N/A", 1); \
        }

static int
ptm_status_bfd(void *m_ctxt, void *in_ctxt, void *out_ctxt)
{
    ptm_status_ctxt_t *p_ctxt = {0};
    bfd_status_ctxt_t *b_ctxt = {0};
    struct ptm_conf_port *port = NULL;
    bfd_sess_parms *topo_parms;
    bfd_sess_parms *sess_parms, *tmp_sess;
    char liface[MAXNAMELEN];
    char state_buf[MAXNAMELEN];
    char status_buf[MAXNAMELEN];
    char peer_buf[MAXNAMELEN];
    char local_buf[MAXNAMELEN];
    char diag_buf[MAXNAMELEN];
    char det_mult[MAXNAMELEN];
    char tx_timeout[MAXNAMELEN];
    char rx_timeout[MAXNAMELEN];
    char echo_tx_timeout[MAXNAMELEN];
    char echo_rx_timeout[MAXNAMELEN];
    char type_buf[MAXNAMELEN];
    char max_hop_cnt[MAXNAMELEN];
    char tx_ctrl[MAXNAMELEN];
    char rx_ctrl[MAXNAMELEN];
    char tx_echo[MAXNAMELEN];
    char rx_echo[MAXNAMELEN];
    char val[MAXNAMELEN] = {0};
    char modstr[MAXNAMELEN] = {0};
    char uptime[MAXNAMELEN];
    char id[MAXNAMELEN];
    bfd_session *bfd = NULL, *tmp, *best_bfd = NULL;
    int detail = FALSE;
    int bfd_only = FALSE;
    int set_env = FALSE;
    char client_buf[MAXNAMELEN] = {0};
    char vrf_name_buf[MAXNAMELEN];

    /* figure out the params */
    if (!ptm_lib_find_key_in_msg(in_ctxt, "module", modstr)) {
        if (!strcasecmp(modstr, ptm_module_string(BFD_MODULE))) {
            bfd_only = TRUE;
            b_ctxt = m_ctxt;
            bfd = b_ctxt->bfd;
            set_env = b_ctxt->set_env_var;
        } else if (!strcasecmp(modstr, ptm_module_string(CONF_MODULE))) {
            p_ctxt = m_ctxt;
            port = p_ctxt->port;
            set_env = p_ctxt->set_env_var;
        } else {
            /* not the relevant module */
            return PTM_CMD_OK;
        }
    } else {
        /* no module specified - assume default */
        p_ctxt = m_ctxt;
        port = p_ctxt->port;
        set_env = p_ctxt->set_env_var;
    }

    if (!ptm_lib_find_key_in_msg(in_ctxt, "detail", val) &&
        !strcasecmp(val, "yes"))
        detail = TRUE;

    /* init defaults */
    strcpy(liface, "N/A");
    strcpy(type_buf, "N/A");
    strcpy(state_buf, "N/A");
    strcpy(status_buf, "N/A");
    strcpy(local_buf, "N/A");
    strcpy(peer_buf, "N/A");
    strcpy(diag_buf, "N/A");
    sprintf(det_mult, "N/A");
    sprintf(tx_timeout, "N/A");
    sprintf(rx_timeout, "N/A");
    sprintf(echo_tx_timeout, "N/A");
    sprintf(echo_rx_timeout, "N/A");
    sprintf(max_hop_cnt, "N/A");
    sprintf(rx_ctrl, "N/A");
    sprintf(tx_ctrl, "N/A");
    sprintf(rx_echo, "N/A");
    sprintf(tx_echo, "N/A");
    sprintf(client_buf, "N/A");
    sprintf(vrf_name_buf, "N/A");

    if (port) {
        char best_peer[MAXNAMELEN] = {0};
        char tmp_peer[MAXNAMELEN] = {0};
        HASH_ITER(ph, peer_hash, bfd, tmp) {

            HASH_FIND(ch, bfd->parm_hash, CLIENT_NAME_DFLT,
                      strlen(CLIENT_NAME_DFLT), topo_parms);

            if (!topo_parms)
                continue;

            if (strcmp(topo_parms->port_name, port->port_name))
                continue;

            /* found bfd session with specified interface */
            ptm_ipaddr_net2str(&bfd->shop.peer, tmp_peer);

            /* check if get-next or specific bfd session requested */
            if (p_ctxt->bfd_get_next) {
                /* get the next best session */
                if (strcmp(p_ctxt->bfd_peer, tmp_peer) < 0) {
                    if (!strlen(best_peer)) {
                        best_bfd = bfd;
                        strcpy(best_peer, tmp_peer);
                    } else if (strcmp(best_peer, tmp_peer) > 0) {
                        best_bfd = bfd;
                        strcpy(best_peer, tmp_peer);
                    }
                }
            } else {
                /* get the specified session */
                if (!strcmp(p_ctxt->bfd_peer, tmp_peer)) {
                    best_bfd = bfd;
                    strcpy(p_ctxt->bfd_peer, peer_buf);
                    break;
                }
            }
        }
        bfd = best_bfd;
        strcpy(p_ctxt->bfd_peer, best_peer);
    }

    if (bfd) {

        if (detail)
            sprintf(state_buf, "%s", state_list[bfd->ses_state].str);
        else
            sprintf(state_buf, "%s",
                (bfd->ses_state == PTM_BFD_UP)? "Up":"Down");

        sprintf(status_buf, "%s",
                (bfd->ses_state == PTM_BFD_UP)? "pass":"fail");

        if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH)) {
            ptm_ipaddr_net2str(&bfd->mhop.peer, peer_buf);
            ptm_ipaddr_net2str(&bfd->mhop.local, local_buf);
        } else {
            ptm_ipaddr_net2str(&bfd->shop.peer, peer_buf);
            ptm_ipaddr_net2str(&bfd->local_ip, local_buf);
        }

        HASH_ITER(ch, bfd->parm_hash, sess_parms, tmp_sess) {break;}
        if (strlen(sess_parms->port_name))
            strcpy(liface, sess_parms->port_name);
        if (strlen(sess_parms->parms.vrf_name))
            strcpy(vrf_name_buf, sess_parms->parms.vrf_name);
        sprintf(client_buf, "%d", HASH_CNT(ch, bfd->parm_hash));

        if (bfd->local_diag)
            sprintf(diag_buf, "%s", get_diag_str(bfd->local_diag));

        sprintf(type_buf, "%s", (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH))
                                    ? "multihop":"singlehop");

        sprintf(det_mult, "%d", bfd->remote_detect_mult);
        sprintf(tx_timeout, "%llu",
                (unsigned long long) (bfd->xmt_TO / NSEC_PER_MSEC));
        sprintf(rx_timeout, "%llu",
                (unsigned long long) (bfd->detect_TO / NSEC_PER_MSEC));
        sprintf(echo_tx_timeout, "%llu",
                (unsigned long long) (bfd->echo_xmt_TO / NSEC_PER_MSEC));
        sprintf(echo_rx_timeout, "%llu",
                (unsigned long long) (bfd->echo_detect_TO / NSEC_PER_MSEC));
        if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH)) {
            sprintf(max_hop_cnt, "%d", bfd->mh_ttl);
        }
        sprintf(rx_ctrl, "%llu",(unsigned long long)bfd->stats.rx_ctrl_pkt);
        sprintf(tx_ctrl, "%llu",(unsigned long long)bfd->stats.tx_ctrl_pkt);
        sprintf(rx_echo, "%llu",(unsigned long long)bfd->stats.rx_echo_pkt);
        sprintf(tx_echo, "%llu",(unsigned long long)bfd->stats.tx_echo_pkt);
        ptm_bfd_sess_up_time(&bfd->up_time, uptime, MAXNAMELEN);
        sprintf(id, "%d", bfd->discrs.my_discr);
    }

    /* start adding data */
    if (bfd_only) {
        PTM_LIB_APPEND_BFD("port", liface);
        PTM_LIB_APPEND_BFD("peer", peer_buf);
        PTM_LIB_APPEND_BFD("state", state_buf);
        PTM_LIB_APPEND_BFD("local", local_buf);
        PTM_LIB_APPEND_BFD("type", type_buf);
        PTM_LIB_APPEND_BFD("diag", diag_buf);
        PTM_LIB_APPEND_BFD("vrf", vrf_name_buf);

        if (detail) {
            PTM_LIB_APPEND_BFD("det mult", det_mult);
            PTM_LIB_APPEND_BFD("tx_timeout", tx_timeout);
            PTM_LIB_APPEND_BFD("rx_timeout", rx_timeout);
            PTM_LIB_APPEND_BFD("echo tx_timeout", echo_tx_timeout);
            PTM_LIB_APPEND_BFD("echo rx_timeout", echo_rx_timeout);
            PTM_LIB_APPEND_BFD("max hop_cnt", max_hop_cnt);
            PTM_LIB_APPEND_BFD("rx_ctrl", rx_ctrl);
            PTM_LIB_APPEND_BFD("tx_ctrl", tx_ctrl);
            PTM_LIB_APPEND_BFD("rx_echo", rx_echo);
            PTM_LIB_APPEND_BFD("tx_echo", tx_echo);
            PTM_LIB_APPEND_BFD("uptime", uptime);
            PTM_LIB_APPEND_BFD("id", id);
            PTM_LIB_APPEND_BFD("client(s)", client_buf);
        }

        if (set_env) {
            UPDATE_ENV_VAR(PTM_ENV_VAR_PORT, liface);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDSTATUS, status_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDPEER, peer_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDLOCAL, local_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDTYPE, type_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDDOWNDIAG, diag_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDVRF, vrf_name_buf);
        }

    } else {
        PTM_LIB_APPEND_BFD("BFD status", status_buf);
        PTM_LIB_APPEND_BFD("BFD peer", peer_buf);
        PTM_LIB_APPEND_BFD("BFD local", local_buf);
        PTM_LIB_APPEND_BFD("BFD type", type_buf);
        if (detail)
            PTM_LIB_APPEND_BFD("BFD DownDiag", diag_buf);

        if (set_env) {
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDSTATUS, status_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDPEER, peer_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDLOCAL, local_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDTYPE, type_buf);
            UPDATE_ENV_VAR(PTM_ENV_VAR_BFDDOWNDIAG, diag_buf);
        }
    }

    return (PTM_CMD_OK);
}

static int ptm_bfd_echo_sock_init(void)
{
    int s;
    int ds;
    int flags;
    struct sockaddr_in sin;
    struct sock_fprog bpf =
    {
        .len = sizeof(bfd_echo_filter) / sizeof (bfd_echo_filter[0]),
        .filter = bfd_echo_filter
    };

    if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        CRITLOG("Can't get Echo packet receive socket: %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    /* Add socket to select */
    PTM_MODULE_SET_FD(ptm_bfd.gbl, s, BFD_MODULE, BFD_ECHO_FD);

    if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        CRITLOG("Setting Echo packet socket filter failed: %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    ptm_bfd.echo_sock = s;

    /* Make UDP socket to listen for echo packets */
    flags = SOCK_DGRAM | SOCK_CLOEXEC;
    if ((ds = socket(PF_INET, flags, IPPROTO_UDP)) < 0) {
        CRITLOG("Can't get echo socket: %m\n");
        return(-1);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(BFD_DEF_ECHO_PORT);
    if (bind(ds, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        CRITLOG("Can't bind socket to default echo port %d: %m\n",
                BFD_DEF_ECHO_PORT);
        return(-1);
    }
    return 0;
}

static void
_fetch_portname_from_ifindex (int ifindex, int sd, char *if_name)
{
    struct ifreq ifr;

    memset(&ifr, 0x00, sizeof(ifr));
    ifr.ifr_ifindex = ifindex;

    if (ioctl(sd, SIOCGIFNAME, &ifr) == -1) {
        CRITLOG("Getting ifname for ifindex %d failed: %m\n", ifindex);
        return;
    }

    memcpy(if_name, ifr.ifr_name, sizeof(ifr.ifr_name));
}

static int ptm_bfd_fetch_ifindex (char *if_name, int sd)
{
    struct ifreq ifr;
    size_t if_name_len = strlen(if_name);

    if (if_name_len && if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
        CRITLOG("Interface name %s incorrect length (%d)\n",
                if_name, (int)if_name_len);
    }

    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        CRITLOG("Getting ifindex for %s failed: %m\n", if_name);
        return -1;
    }
    return ifr.ifr_ifindex;
}

static void ptm_bfd_fetch_local_mac (char *if_name, int sd, uint8_t *local_mac)
{
    struct ifreq ifr;
    size_t if_name_len = strlen(if_name);

    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
        CRITLOG("Interface name %s is too long\n", if_name);
    }

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        CRITLOG("Getting mac address for %s failed: %m\n", if_name);
        return;
    }

    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
}

uint16_t ptm_bfd_gen_IP_ID(bfd_session *bfd)
{
    return(++bfd->ip_id);
}

void ptm_bfd_echo_pkt_create(bfd_session *bfd)
{
    bfd_raw_echo_pkt_t ep;
    uint8_t *pkt = bfd->echo_pkt;

    memset(&ep, 0, sizeof(bfd_raw_echo_pkt_t));
    memset(bfd->echo_pkt, 0, BFD_ECHO_PKT_TOT_LEN);

    /* Construct ethernet header information */
    memcpy(pkt, bfd->peer_mac, ETH_ALEN);
    pkt = pkt + ETH_ALEN;
    memcpy(pkt, bfd->local_mac, ETH_ALEN);
    pkt = pkt + ETH_ALEN;
    pkt[0] = ETH_P_IP / 256;
    pkt[1] = ETH_P_IP % 256;
    pkt += 2;

    /* Construct IP header information */
    ep.ip.version = 4;
    ep.ip.ihl = 5;
    ep.ip.tos = 0;
    ep.ip.tot_len = htons(IP_ECHO_PKT_LEN);
    ep.ip.id = htons(ptm_bfd_gen_IP_ID(bfd));
    ep.ip.frag_off = 0;
    ep.ip.ttl = BFD_TTL_VAL;
    ep.ip.protocol = IPPROTO_UDP;
    ep.ip.saddr = bfd->local_ip.ip4_addr.s_addr;
    ep.ip.daddr = bfd->shop.peer.ip4_addr.s_addr;
    ep.ip.check = checksum((uint16_t *)&ep.ip, IP_HDR_LEN);

    /* Construct UDP header information */
    ep.udp.source = htons(BFD_DEF_ECHO_PORT);
    ep.udp.dest = htons(BFD_DEF_ECHO_PORT);
    ep.udp.len = htons(UDP_ECHO_PKT_LEN);

    /* Construct Echo packet information */
    ep.data.ver = BFD_ECHO_VERSION;
    ep.data.len = BFD_ECHO_PKT_LEN;
    ep.data.my_discr = htonl(bfd->discrs.my_discr);
    ep.udp.check = udp4_checksum (&ep.ip, (uint8_t *)&ep.udp,
                                    UDP_ECHO_PKT_LEN);

    memcpy (pkt, &ep, sizeof(bfd_raw_echo_pkt_t));
}

void ptm_bfd_echo_snd(bfd_session *bfd)
{
    struct sockaddr_ll dll;
    bfd_raw_echo_pkt_t *ep;

    memset(&dll, 0, sizeof(struct sockaddr_ll));

    if (!BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
        ptm_bfd_echo_pkt_create(bfd);
        BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);
    }
    else {
        /* just update the checksum and ip Id */
        ep = (bfd_raw_echo_pkt_t *)(bfd->echo_pkt + ETH_HDR_LEN);
        ep->ip.id = htons(ptm_bfd_gen_IP_ID(bfd));
        ep->ip.check = 0;
        ep->ip.check = checksum((uint16_t *)&ep->ip, IP_HDR_LEN);
    }

    // Fill out sockaddr_ll.
    dll.sll_family = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_IP);
    memcpy (dll.sll_addr, bfd->peer_mac, ETH_ALEN);
    dll.sll_halen = htons (6);
    dll.sll_ifindex = bfd->ifindex;

    if (sendto(ptm_bfd.echo_sock, bfd->echo_pkt, BFD_ECHO_PKT_TOT_LEN, 0,
                (struct sockaddr *)&dll, sizeof(struct sockaddr_ll)) < 0) {
        ERRLOG("Error sending echo pkt: %m\n");
    } else {
        bfd->stats.tx_echo_pkt++;
    }
}

int  ptm_bfd_echo_loopback(void *pkt, int pkt_len, struct sockaddr_ll *sll)
{
    bfd_raw_echo_pkt_t *ep = (bfd_raw_echo_pkt_t *)(pkt + ETH_HDR_LEN);
    uint32_t temp_ip;
    uint8_t temp_mac[ETH_ALEN];
    struct ethhdr *eth = (struct ethhdr *) pkt;

    /* swap the mac addresses */
    memcpy (temp_mac, eth->h_source, ETH_ALEN);
    memcpy (eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy (eth->h_dest, temp_mac, ETH_ALEN);

    /* swap ip addresses */
    temp_ip = ep->ip.saddr;
    ep->ip.saddr = ep->ip.daddr;
    ep->ip.daddr = temp_ip;

    ep->ip.ttl = ep->ip.ttl - 1;
    ep->ip.check = 0;
    ep->ip.check = checksum((uint16_t *)ep, IP_HDR_LEN);

    if (sendto(ptm_bfd.echo_sock, pkt, pkt_len, 0, (struct sockaddr *)sll,
               sizeof(struct sockaddr_ll)) < 0) {
        ERRLOG("Error sending echo pkt: %m\n");
        return -1;
    }

    return 0;
}

static void ptm_bfd_echo_detect_TO(bfd_session *bfd)
{
    uint8_t old_state;
    char peer_addr[INET6_ADDRSTRLEN];

    old_state = bfd->ses_state;

    switch (bfd->ses_state) {
    case PTM_BFD_INIT:
    case PTM_BFD_UP:
        ptm_bfd_ses_dn(bfd, BFD_DIAGDETECTTIME);
        INFOLOG("%s Detect timeout on session 0x%x with peer %s,"
                " in state %d\n", __FUNCTION__, bfd->discrs.my_discr,
                ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr), bfd->ses_state);
        break;

    default:
        break;
    }

    if (old_state != bfd->ses_state) {
        DLOG("BFD Sess %d [%s] Old State [%s] : New State [%s]\n",
              bfd->discrs.my_discr,
              ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr),
              state_list[old_state].str,
              state_list[bfd->ses_state].str);
    }
}

static void ptm_bfd_start_echo_tx_timer(bfd_session *bfd)
{
    uint64_t jitter;
    int maxpercent;

    /*
     * From section 6.5.2: trasmit interval should be randomly jittered between
     * 75% and 100% of nominal value, unless detect_mult is 1, then should be
     * between 75% and 90%.
     */
    maxpercent = (bfd->detect_mult == 1) ? 16 : 26;
    jitter = (bfd->echo_xmt_TO * (75 + (random() % maxpercent))) / 100;

    /* XXX remove that division above */
    bfd_update_timer(&bfd->echo_xmt_timer, jitter);
}

static void ptm_bfd_echo_xmt_TO(bfd_session *bfd)
{
    /* Send the scheduled echo  packet */
    ptm_bfd_echo_snd(bfd);

    /* Restart the timer for next time */
    ptm_bfd_start_echo_tx_timer(bfd);
}

static void ptm_bfd_echo_start(bfd_session *bfd)
{
    ptm_bfd_echo_xmt_TO(bfd);

    bfd->echo_detect_TO = (bfd->remote_detect_mult * bfd->echo_xmt_TO);
    bfd_update_timer(&bfd->echo_detect_timer, bfd->echo_detect_TO);

    bfd->polling = 1;
    bfd->new_timers.desired_min_tx = bfd->slow_min_tx;
    bfd->new_timers.required_min_rx = bfd->timers.required_min_rx;
    ptm_bfd_snd(bfd, 0);
}

static void ptm_bfd_echo_stop(bfd_session *bfd, int polling)
{
    bfd->echo_xmt_TO = 0;
    bfd->echo_detect_TO = 0;
    BFD_UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);
    if (polling) {
        bfd->polling = polling;
        bfd->new_timers.desired_min_tx = bfd->up_min_tx;
        bfd->new_timers.required_min_rx = bfd->timers.required_min_rx;
        ptm_bfd_snd(bfd, 0);
    }
}

static int ptm_bfd_process_echo_pkt(int s, ptm_sockevent_e se, void *udata)
{
    int pkt_len;
    struct sockaddr_ll sll;
    uint32_t from_len = sizeof(struct sockaddr_ll);
    bfd_raw_echo_pkt_t *ep;
    char rx_pkt[BFD_RX_BUF_LEN];
    bfd_session *bfd;
    uint32_t my_discr = 0;

    DLOG("receiving from BFD Echo socket\n");
    pkt_len = recvfrom(s, rx_pkt, BFD_RX_BUF_LEN, MSG_DONTWAIT,
                                  (struct sockaddr *)&sll, &from_len);

    if (pkt_len  < 0) {
        if (errno != EAGAIN) {
            ERRLOG("Error receiving from BFD Echo socket: %m\n");
        }
        return -1;
    }

    ep = (bfd_raw_echo_pkt_t *)(rx_pkt + ETH_HDR_LEN);

    /* if TTL = 255, assume that the received echo packet has
     * to be looped back */
    if (ep->ip.ttl == BFD_TTL_VAL) {
        return ptm_bfd_echo_loopback((void *)rx_pkt, pkt_len, &sll);
    }

    if (pkt_len < BFD_ECHO_PKT_TOT_LEN) {
        INFOLOG("Received short echo packet from 0x%x\n",
                    ntohl(ep->ip.saddr));
        return -1;
    }

    if (ep->data.my_discr == 0) {
        INFOLOG("My discriminator is zero in echo pkt from 0x%x\n",
                    ntohl(ep->ip.saddr));
        return -1;
    }

    /* Your discriminator not zero - use it to find session */
    my_discr = ntohl(ep->data.my_discr);
    HASH_FIND(sh, session_hash, &my_discr, sizeof(int), bfd);

    if (bfd == NULL) {
        INFOLOG("Failed to extract session from echo packet\n");
        return -1;
    }

    if (!BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
        INFOLOG("BFD echo not active - ignore echo packet\n");
        return -1;
    }

    bfd->stats.rx_echo_pkt++;

    /* Compute detect time */
    bfd->echo_detect_TO = bfd->remote_detect_mult * bfd->echo_xmt_TO;

    /* Restart detection timer (packet received) */
    bfd_update_timer(&bfd->echo_detect_timer, bfd->echo_detect_TO);

    return 0;
}

void
ptm_bfd_vxlan_pkt_snd(bfd_session *bfd, int fbit)
{
    bfd_raw_ctrl_pkt_t cp;
    uint8_t vxlan_pkt[BFD_VXLAN_PKT_TOT_LEN];
    uint8_t *pkt = vxlan_pkt;
    struct sockaddr_in sin;
    vxlan_hdr_t *vhdr;

    memset(pkt, 0, BFD_VXLAN_PKT_TOT_LEN);
    memset(&cp, 0, sizeof(bfd_raw_ctrl_pkt_t));

    /* Construct VxLAN header information */
    vhdr = (vxlan_hdr_t *)pkt;
    vhdr->flags = htonl(0x08000000);
    vhdr->vnid = htonl(bfd->vxlan_info.vnid << 8);
    pkt += VXLAN_HDR_LEN;

    /* Construct ethernet header information */
    memcpy(pkt, bfd->vxlan_info.peer_dst_mac, ETH_ALEN);
    pkt = pkt + ETH_ALEN;
    memcpy(pkt, bfd->vxlan_info.local_dst_mac, ETH_ALEN);
    pkt = pkt + ETH_ALEN;
    pkt[0] = ETH_P_IP / 256;
    pkt[1] = ETH_P_IP % 256;
    pkt += 2;

    /* Construct IP header information */
    cp.ip.version = 4;
    cp.ip.ihl = 5;
    cp.ip.tos = 0;
    cp.ip.tot_len = htons(IP_CTRL_PKT_LEN);
    cp.ip.id = ptm_bfd_gen_IP_ID(bfd);
    cp.ip.frag_off = 0;
    cp.ip.ttl = BFD_TTL_VAL;
    cp.ip.protocol = IPPROTO_UDP;
    cp.ip.daddr = bfd->vxlan_info.peer_dst_ip.s_addr;
    cp.ip.saddr = bfd->vxlan_info.local_dst_ip.s_addr;
    cp.ip.check = checksum((uint16_t *)&cp.ip, IP_HDR_LEN);

    /* Construct UDP header information */
    cp.udp.source = htons(BFD_DEFDESTPORT);
    cp.udp.dest = htons(BFD_DEFDESTPORT);
    cp.udp.len = htons(UDP_CTRL_PKT_LEN);

    /* Construct BFD control packet information */
    cp.data.diag = bfd->local_diag;
    BFD_SETVER(cp.data.diag, BFD_VERSION);
    BFD_SETSTATE(cp.data.flags, bfd->ses_state);
    BFD_SETDEMANDBIT(cp.data.flags, BFD_DEF_DEMAND);
    BFD_SETPBIT(cp.data.flags, bfd->polling);
    BFD_SETFBIT(cp.data.flags, fbit);
    cp.data.detect_mult = bfd->detect_mult;
    cp.data.len = BFD_PKT_LEN;
    cp.data.discrs.my_discr = htonl(bfd->discrs.my_discr);
    cp.data.discrs.remote_discr = htonl(bfd->discrs.remote_discr);
    cp.data.timers.desired_min_tx = htonl(bfd->timers.desired_min_tx);
    cp.data.timers.required_min_rx = htonl(bfd->timers.required_min_rx);
    cp.data.timers.required_min_echo = htonl(bfd->timers.required_min_echo);

    cp.udp.check = udp4_checksum (&cp.ip, (uint8_t *)&cp.udp,
                                    UDP_CTRL_PKT_LEN);

    memcpy (pkt, &cp, sizeof(bfd_raw_ctrl_pkt_t));
    sin.sin_family = AF_INET;
    sin.sin_addr = bfd->shop.peer.ip4_addr;
    sin.sin_port = htons(4789);

    if (sendto(bfd->sock, vxlan_pkt, BFD_VXLAN_PKT_TOT_LEN, 0,
            (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) {
        ERRLOG("Error sending vxlan bfd pkt: %m\n");
    } else {
        bfd->stats.tx_ctrl_pkt++;
    }
}

static int
ptm_bfd_vxlan_sock_init(void)
{
    int s;
    struct sock_fprog bpf =
    {
        .len = sizeof(bfd_vxlan_filter) / sizeof (bfd_vxlan_filter[0]),
        .filter = bfd_vxlan_filter
    };

    if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        CRITLOG("Can't get VxLAN packet receive socket: %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    /* Add socket to select */
    PTM_MODULE_SET_FD(ptm_bfd.gbl, s, BFD_MODULE, BFD_VXLAN_FD);

    if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        CRITLOG("Setting VxLAN packet socket filter failed: %m\n");
        ptm_shutdown_bfd(ptm_bfd.gbl);
        return(-1);
    }

    ptm_bfd.vxlan_sock = s;

    return 0;
}

static bfd_pkt_t *
ptm_bfd_process_vxlan_pkt(int                       s,
                          ptm_sockevent_e           se,
                          void                      *udata,
                          int                       *ifindex,
                          struct sockaddr_in        *sin,
                          bfd_session_vxlan_info_t  *vxlan_info,
                          uint8_t                   *rx_pkt,
                          int                       *mlen)
{
    struct sockaddr_ll sll;
    uint32_t from_len = sizeof(struct sockaddr_ll);
    bfd_raw_ctrl_pkt_t *cp;
    uint8_t *pkt = rx_pkt;
    struct iphdr *iph;
    struct ethhdr *inner_ethh;

    *mlen = recvfrom(s, rx_pkt, BFD_RX_BUF_LEN, MSG_DONTWAIT,
                                  (struct sockaddr *)&sll, &from_len);

    if (*mlen  < 0) {
        if (errno != EAGAIN) {
            ERRLOG("Error receiving from BFD Vxlan socket %d: %m\n", s);
        }
        return NULL;
    }

    iph = (struct iphdr *)(pkt + ETH_HDR_LEN);
    pkt = pkt + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    vxlan_info->vnid = ntohl(*((int *)(pkt + 4)));
    vxlan_info->vnid = vxlan_info->vnid >> 8;

    pkt = pkt + VXLAN_HDR_LEN;
    inner_ethh = (struct ethhdr *)pkt;

    cp = (bfd_raw_ctrl_pkt_t *)(pkt + ETH_HDR_LEN);

    /* Discard the non BFD packets */
    if (ntohs(cp->udp.dest) != BFD_DEFDESTPORT)
        return NULL;

    *ifindex = sll.sll_ifindex;
    sin->sin_addr.s_addr = iph->saddr;
    sin->sin_port = ntohs(cp->udp.dest);

    vxlan_info->local_dst_ip.s_addr = cp->ip.daddr;
    memcpy(vxlan_info->local_dst_mac, inner_ethh->h_dest, ETH_ALEN);

    return (&cp->data);
}

bool
ptm_bfd_validate_vxlan_pkt(bfd_session *bfd,
                           bfd_session_vxlan_info_t *vxlan_info)
{
    if (bfd->vxlan_info.check_tnl_key && (vxlan_info->vnid != 0)) {
        ERRLOG("Error Rx BFD Vxlan pkt with non-zero vnid %d\n",
                vxlan_info->vnid);
        return false;
    }

    if (bfd->vxlan_info.local_dst_ip.s_addr
                    != vxlan_info->local_dst_ip.s_addr) {
        ERRLOG("Error Rx BFD Vxlan pkt with wrong inner dst IP %s\n",
                inet_ntoa(vxlan_info->local_dst_ip));
        return false;
    }

    if (memcmp(bfd->vxlan_info.local_dst_mac, vxlan_info->local_dst_mac,
                ETH_ALEN)) {
        ERRLOG("Error Rx BFD Vxlan pkt with wrong inner dst"
                " MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                vxlan_info->local_dst_mac[0],
                vxlan_info->local_dst_mac[1],
                vxlan_info->local_dst_mac[2],
                vxlan_info->local_dst_mac[3],
                vxlan_info->local_dst_mac[4],
                vxlan_info->local_dst_mac[5]);
        return false;
    }

    return true;
}

static bfd_sess_parms *
ptm_bfd_alloc_sess_parms(void)
{
    bfd_sess_parms *entry;

    entry = (bfd_sess_parms *)calloc(1, sizeof(bfd_sess_parms));
    if (!entry) {
        ERRLOG("%s: Could not alloc parm entry\n", __FUNCTION__);
        return NULL;
    }

    /* Initialize param defaults with global defaults */
    PTM_BFD_SET_PARM(&entry->parms, detect_mult,
            PTM_BFD_GET_GLOBAL_PARM(detect_mult));
    PTM_BFD_SET_PARM(&entry->parms, up_min_tx,
            PTM_BFD_GET_GLOBAL_PARM(up_min_tx));
    PTM_BFD_SET_PARM(&entry->parms, timers.required_min_rx,
            PTM_BFD_GET_GLOBAL_PARM(timers.required_min_rx));
    PTM_BFD_SET_PARM(&entry->parms, timers.required_min_echo,
            PTM_BFD_GET_GLOBAL_PARM(timers.required_min_echo));
    PTM_BFD_SET_PARM(&entry->parms, slow_min_tx,
            PTM_BFD_GET_GLOBAL_PARM(slow_min_tx));
    PTM_BFD_SET_PARM(&entry->parms, mh_ttl,
            PTM_BFD_GET_GLOBAL_PARM(mh_ttl));
    PTM_BFD_SET_PARM(&entry->parms, afi,
            PTM_BFD_GET_GLOBAL_PARM(afi));
    PTM_BFD_SET_PARM(&entry->parms, send_event,
            PTM_BFD_GET_GLOBAL_PARM(send_event));
    PTM_BFD_SET_PARM(&entry->parms, echo_support,
            PTM_BFD_GET_GLOBAL_PARM(echo_support));

    strcpy(entry->client.name, CLIENT_NAME_DFLT);
    entry->client.seqid = CLIENT_SEQID_DFLT;

    return entry;
}

static void
_incr_client_num_sessions(char *name, bool pend)
{
    ptm_bfd_client_t *client;

    client = _get_client_info_by_name(name);

    if (client) {
        if (pend)
            client->num_pend_sessions++;
        else
            client->num_sessions++;
    }
}

static void
_decr_client_num_sessions(char *name, bool pend)
{
    ptm_bfd_client_t *client;

    client = _get_client_info_by_name(name);

    if (client) {
        if (pend)
            client->num_pend_sessions--;
        else
            client->num_sessions--;
        /* dont delete topo client */
        if (!client->num_pend_sessions &&
            !client->num_sessions &&
            strcmp(client->name, CLIENT_NAME_DFLT)) {
            _del_client_info(name);
        }
    }
}

static ptm_bfd_client_t *
_get_client_info_by_name(char *name)
{
    int i;

    for (i = 0; i < MAX_CLIENTS; i++) {
        if (!strcmp(ptm_bfd.clients[i].name, name)) {
            return &ptm_bfd.clients[i];
        }
    }

    return NULL;
}

static ptm_bfd_client_t *
_get_client_info_by_idx(int idx)
{
    if (idx >= 0 && idx < MAX_CLIENTS) {
        return &ptm_bfd.clients[idx];
    }

    return NULL;
}

static void
_del_client_info(char *name)
{
    int i;
    ptm_bfd_client_t *client;

    for (i = 0; i < MAX_CLIENTS; i++) {
        client = &ptm_bfd.clients[i];
        if (!strcmp(client->name, name)) {
            memset(client, 0x00, sizeof(*client));
            ptm_bfd.num_clients--;
            return;
        }
    }
}

static ptm_bfd_client_t *
_add_client_info(char *name, int seqid)
{
    int i;

    if (ptm_bfd.num_clients < MAX_CLIENTS) {
        for (i = 0; i < MAX_CLIENTS; i++) {
            if (!ptm_bfd.clients[i].seqid) {
                strcpy(ptm_bfd.clients[i].name, name);
                ptm_bfd.clients[i].seqid = seqid;
                ptm_bfd.num_clients++;
                return &ptm_bfd.clients[i];
            }
        }
    }
    return NULL;
}

static int
ptm_bfd_get_client_list(ptm_client_t *client, void *in_ctxt, char *errstr)
{
    char *msgbuf;
    int msglen;
    char val[MAXNAMELEN] = {0};
    char seqid[MAXNAMELEN], num_sess[MAXNAMELEN];
    char pend_sess[MAXNAMELEN];
    int i, rval = PTM_CMD_OK, found;
    ptm_bfd_client_t *bfd_client;
    void *out_ctxt = NULL;

    INFOLOG("get bfd client list\n");

    ptm_lib_find_key_in_msg(in_ctxt, CLIENT_NAME, val);

    sprintf(errstr, "BFD Internal error");

    if ((msgbuf = malloc(CTL_MSG_SZ)) == NULL) {
        ERRLOG("%s: %s\n", __FUNCTION__, errstr);
        return (PTM_CMD_ERROR);
    }

    found = 0;
    for(i = 0; i < MAX_CLIENTS; i++) {

        bfd_client = &ptm_bfd.clients[i];

        if (!bfd_client->seqid) continue;

        if (strlen(val) && strcasecmp(val, bfd_client->name))
            continue;

        sprintf(seqid, "%d", bfd_client->seqid);
        sprintf(num_sess, "%d", bfd_client->num_sessions);
        sprintf(pend_sess, "%d", bfd_client->num_pend_sessions);

        ptm_lib_init_msg(ptm_bfd.gbl->ptmlib_hdl, 0,
                     PTMLIB_MSG_TYPE_RESPONSE, NULL, &out_ctxt);

        PTM_LIB_APPEND_BFD("Name", bfd_client->name);
        PTM_LIB_APPEND_BFD("SeqId", seqid);
        PTM_LIB_APPEND_BFD("Num Sessions", num_sess);
        PTM_LIB_APPEND_BFD("Pending Sessions", pend_sess);

        msglen = CTL_MSG_SZ;
        ptm_lib_complete_msg(ptm_bfd.gbl->ptmlib_hdl, out_ctxt, msgbuf, &msglen);

        DLOG("Sending %s\n", msgbuf);
        ptm_ctl_send(client, msgbuf, msglen);

        found = 1;
    } /* end iter loop */

    free(msgbuf);

    if (rval != PTM_CMD_OK) {
        return (rval);
    }

    if (!found) {
        sprintf(errstr, "No BFD clients");
        INFOLOG("%s: %s\n", __FUNCTION__, errstr);
        return (PTM_CMD_ERROR);
    }

    return (PTM_CMD_OK);
}

static int
ptm_bfd_get_client_sess(ptm_client_t *client, void *in_ctxt, char *errstr)
{
    bfd_sess_parms *entry, *tmp;
    char *msgbuf;
    int msglen = CTL_MSG_SZ;
    char val[MAXNAMELEN] = {0};
    char client_name[MAXNAMELEN] = {0};
    char local_portname[MAXNAMELEN+1] = {0};
    char peer_buf[32], local_buf[32], port_buf[32];
    char seqid[32], vnid_buf[32], type_buf[32];
    char l_dmac_buf[32], l_dip_buf[32];
    char r_dmac_buf[32], r_dip_buf[32];
    char decay_min_rx_buf[32], fwd_if_fx_buf[32];
    char cpath_down_buf[32], check_tnl_key_buf[32];
    char min_rx[32], min_tx[32], detect_mult[32];
    char state_buf[MAXNAMELEN];
    char diag_buf[MAXNAMELEN];
    ptm_ipaddr peer, local;
    bfd_session *bfd;
    int rval = PTM_CMD_OK, found;
    void *out_ctxt = NULL;
    int detail = FALSE;
    char vrf_name_buf[MAXNAMELEN+1] = {0};

    INFOLOG("get bfd client sess \n");

    sprintf(errstr, "BFD Internal error");

    if ((msgbuf = malloc(CTL_MSG_SZ)) == NULL) {
        ERRLOG("%s: %s\n", __FUNCTION__, errstr);
        return (PTM_CMD_ERROR);
    }

    ptm_lib_find_key_in_msg(in_ctxt, CLIENT_NAME, client_name);

    found = 0;
    if (!ptm_lib_find_key_in_msg(in_ctxt, "detail", val) &&
        !strcasecmp(val, "yes"))
        detail = TRUE;

    HASH_ITER(ciph, sess_parm_hash, entry, tmp) {

        if (strlen(client_name) && strcasecmp(client_name, entry->client.name))
            continue;

        ptm_lib_init_msg(ptm_bfd.gbl->ptmlib_hdl, 0,
                     PTMLIB_MSG_TYPE_RESPONSE, NULL, &out_ctxt);

        strcpy(peer_buf, entry->parms.dst_ipaddr);
        strcpy(local_buf, "N/A");
        strcpy(port_buf, "N/A");
        strcpy(vnid_buf, "N/A");
        strcpy(l_dip_buf, "N/A");
        strcpy(r_dip_buf, "N/A");
        strcpy(state_buf, "Down");
        strcpy(diag_buf, "N/A");
        strcpy(vrf_name_buf, "N/A");

        if (strlen(entry->parms.src_ipaddr))
            strcpy(local_buf, entry->parms.src_ipaddr);
        if (strlen(entry->port_name))
            strcpy(port_buf, entry->port_name);
        sprintf(seqid, "%d", entry->client.seqid);
        if (entry->parms.enable_vnid)
            sprintf(vnid_buf, "%d", entry->parms.vnid);
        sprintf(type_buf, "%s",
            (entry->parms.multi_hop)?"multihop":"singlehop");

        sprintf(l_dmac_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                entry->parms.local_dst_mac[0], entry->parms.local_dst_mac[1],
                entry->parms.local_dst_mac[2], entry->parms.local_dst_mac[3],
                entry->parms.local_dst_mac[4], entry->parms.local_dst_mac[5]);

        if (strlen(entry->parms.local_dst_ip))
            strcpy(l_dip_buf, entry->parms.local_dst_ip);

        sprintf(r_dmac_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                entry->parms.remote_dst_mac[0], entry->parms.remote_dst_mac[1],
                entry->parms.remote_dst_mac[2], entry->parms.remote_dst_mac[3],
                entry->parms.remote_dst_mac[4], entry->parms.remote_dst_mac[5]);

        if (strlen(entry->parms.remote_dst_ip))
            strcpy(r_dip_buf, entry->parms.remote_dst_ip);

        sprintf(decay_min_rx_buf, "%d", entry->parms.decay_min_rx);
        sprintf(fwd_if_fx_buf, "%d", entry->parms.forwarding_if_rx);
        sprintf(cpath_down_buf, "%d", entry->parms.cpath_down);
        sprintf(check_tnl_key_buf, "%d", entry->parms.check_tnl_key);

        /* keep in network-byte order */
        ptm_ipaddr_str2net(entry->parms.dst_ipaddr, &peer);
        if (strlen(entry->parms.src_ipaddr))
            ptm_ipaddr_str2net(entry->parms.src_ipaddr, &local);
        else
            memset(&local, 0, sizeof(ptm_ipaddr));

        if (!entry->parms.enable_vnid)
            strcpy(local_portname, entry->parms.ifname);

        if (strlen(entry->parms.vrf_name))
            strcpy(vrf_name_buf, entry->parms.vrf_name);

        /* find the BFD session if it exists */
        bfd = ptm_bfd_sess_find(NULL, local_portname, peer,
                local, vrf_name_buf, entry->parms.multi_hop);

        if (bfd) {
            sprintf(state_buf, "%s",
                (bfd->ses_state == PTM_BFD_UP)? "Up":"Down");

            if (bfd->local_diag)
                sprintf(diag_buf, "%s", get_diag_str(bfd->local_diag));
        }

        PTM_LIB_APPEND_BFD("peer", peer_buf);
        PTM_LIB_APPEND_BFD("local", local_buf);
        PTM_LIB_APPEND_BFD("state", state_buf);
        PTM_LIB_APPEND_BFD("diag", diag_buf);
        PTM_LIB_APPEND_BFD("port", port_buf);
        PTM_LIB_APPEND_BFD("client", entry->client.name);
        PTM_LIB_APPEND_BFD("seqId", seqid);
        PTM_LIB_APPEND_BFD("vnid", vnid_buf);
        PTM_LIB_APPEND_BFD("type", type_buf);
        PTM_LIB_APPEND_BFD("local_dst_mac", l_dmac_buf);
        PTM_LIB_APPEND_BFD("local_dst_ip", l_dip_buf);
        PTM_LIB_APPEND_BFD("remote_dst_mac", r_dmac_buf);
        PTM_LIB_APPEND_BFD("remote_dst_ip", r_dip_buf);
        PTM_LIB_APPEND_BFD("decay_min_rx", decay_min_rx_buf);
        PTM_LIB_APPEND_BFD("forwarding_if_rx", fwd_if_fx_buf);
        PTM_LIB_APPEND_BFD("cpath_down", cpath_down_buf);
        PTM_LIB_APPEND_BFD("check_tnl_key", check_tnl_key_buf);

        if (detail == TRUE) {
            sprintf(min_tx, "%ld", entry->parms.up_min_tx / USEC_PER_MSEC);
            sprintf(min_rx, "%ld",
                        entry->parms.timers.required_min_rx / USEC_PER_MSEC);
            sprintf(detect_mult, "%d", entry->parms.detect_mult);

            PTM_LIB_APPEND_BFD("upMinTx", min_tx);
            PTM_LIB_APPEND_BFD("requiredMinRx", min_rx);
            PTM_LIB_APPEND_BFD("detectMult", detect_mult);
            PTM_LIB_APPEND_BFD("vrfName", vrf_name_buf);

        }
        msglen = CTL_MSG_SZ;
        ptm_lib_complete_msg(ptm_bfd.gbl->ptmlib_hdl, out_ctxt, msgbuf, &msglen);

        DLOG("Sending %s\n", msgbuf);
        ptm_ctl_send(client, msgbuf, msglen);

        found = 1;
    } /* end iter loop */

    free(msgbuf);

    if (rval != PTM_CMD_OK) {
        return (rval);
    }

    if (!found) {
        sprintf(errstr, "No client BFD sessions");
        INFOLOG("%s: %s\n", __FUNCTION__, errstr);
        return (PTM_CMD_ERROR);
    }

    return (PTM_CMD_OK);
}

int
ptm_bfd_get_client_handler(ptm_client_t *client, void *in_ctxt, char *errstr)
{
    char val[MAXNAMELEN] = {0};
    int rval = PTM_CMD_OK;

    INFOLOG("get bfd client\n");

    ptm_lib_find_key_in_msg(in_ctxt, "sessions", val);

    if (!strcasecmp(val, "yes")) {
        rval = ptm_bfd_get_client_sess(client, in_ctxt, errstr);
    } else {
        rval = ptm_bfd_get_client_list(client, in_ctxt, errstr);
    }

    return (rval);
}

static void
handle_bfd_event(ptm_module_e mod,
                 bfd_sess_parms *sess_parms,
                 ptm_event_e ev)
{
    int ip_type;

    if (sess_parms->pend)
        return;

    ptm_event_cleanup(&ptm_bfd.event);

    ptm_bfd.event.module = mod;
    ptm_bfd.event.type = ev;
    ip_type = ptm_ipaddr_get_ip_type(sess_parms->parms.dst_ipaddr);
    if (ip_type == AF_INET) {
        ptm_bfd.event.rv4addr = strdup(sess_parms->parms.dst_ipaddr);
    } else if (ip_type == AF_INET6) {
        ptm_bfd.event.rv6addr = strdup(sess_parms->parms.dst_ipaddr);
        sess_parms->parms.afi = BFD_AFI_V6;
    } else {
        INFOLOG("Unknown dest ip address format %s\n",
                sess_parms->parms.dst_ipaddr);
        return;
    }

    if (strlen(sess_parms->port_name))
        ptm_bfd.event.liface = strdup(sess_parms->port_name);
    if (strlen(sess_parms->parms.src_ipaddr)) {
        ip_type = ptm_ipaddr_get_ip_type(sess_parms->parms.src_ipaddr);
        if (ip_type == AF_INET) {
            ptm_bfd.event.lv4addr = strdup(sess_parms->parms.src_ipaddr);
        } else if (ip_type == AF_INET6) {
            ptm_bfd.event.lv6addr = strdup(sess_parms->parms.src_ipaddr);
        } else {
            INFOLOG("Unknown source ip address format %s\n",
                    sess_parms->parms.src_ipaddr);
            return;
        }
    }

    ptm_bfd.event.bfdtype = (sess_parms->parms.multi_hop)?
                                BFD_MULTI_HOP:BFD_SINGLE_HOP;
    ptm_bfd.event.vnid_present = sess_parms->parms.enable_vnid;
    ptm_bfd.event.vnid = (ptm_bfd.event.vnid_present)?
                                sess_parms->parms.vnid:PTM_BFD_INVALID_VNID;
    ptm_bfd.event.ctxt = _get_client_info_by_name(sess_parms->client.name);

    if (!ptm_bfd.event.ctxt) {
        ERRLOG("Unknown client %s:%s - ignore event\n",
               sess_parms->client.name,
               sess_parms->parms.dst_ipaddr);
        return;
    }

    if (strlen(sess_parms->parms.vrf_name))
        ptm_bfd.event.vrf_name = strdup(sess_parms->parms.vrf_name);
    ptm_peer_event_bfd(&ptm_bfd.event);
}

int
ptm_bfd_start_client_sess(ptm_client_t *client, void *in_ctxt, char *errstr)
{
    bfd_sess_parms *new_parms, *curr_parms;
    parm_key key;
    bfd_parms_list *p;
    ptm_bfd_client_t *bfd_client;
    ptm_event_e ev = EVENT_ADD;
    int err = 0, ifindex, i;

    DLOG("start bfd client session\n");

    sprintf(errstr, "Command failure");

    new_parms = ptm_parse_bfd_params(NULL, in_ctxt);

    if (!new_parms) {
        /* error parsing arguments */
        ERRLOG("error parsing bfd args - not creating session\n");
        return PTM_CMD_ERROR;
    }

    p = &new_parms->parms;

    /* sanity checks */
    if (!strlen(p->dst_ipaddr)) {
        /* remote IP is mandatory */
        ERRLOG("Remote/Dest IP NULL\n");
        err = 1;
    } else if (p->multi_hop && !strlen(p->src_ipaddr)) {
        /* multi-hop needs src IP */
        ERRLOG("multihop session requires src ip\n");
        err = 1;
    } else if ((ptm_ipaddr_get_ip_type(p->dst_ipaddr) == AF_INET6)
                && !strlen(p->src_ipaddr)) {
        /* IPv6 sessions needs src IP */
        ERRLOG("IPv6 session requires src ip\n");
        err = 1;
    } else if (strlen(p->src_ipaddr) &&
               (ptm_ipaddr_get_ip_type(p->dst_ipaddr)) !=
                (ptm_ipaddr_get_ip_type(p->src_ipaddr))) {
        /* Cannot mix-n-match ipv6/ipv4 */
        ERRLOG("Cannot mix IPv4 and IPv6 ip\n");
        err = 1;
    } else if ((ptm_ipaddr_get_ip_type(p->dst_ipaddr) == AF_INET6) &&
               ((ptm_ipaddr_is_ipv6_link_local(p->dst_ipaddr)) !=
                (ptm_ipaddr_is_ipv6_link_local(p->src_ipaddr)))) {
        /* Cannot mix-n-match link-local and non-link-local ipv6 */
        ERRLOG("Cannot mix IPv6 link-local and non-link-local ip\n");
        err = 1;
    } else if ((ptm_ipaddr_get_ip_type(p->dst_ipaddr) == AF_INET6) &&
               ((ptm_ipaddr_is_ipv6_link_local(p->dst_ipaddr)) &&
                (ptm_ipaddr_is_ipv6_link_local(p->src_ipaddr))) &&
               p->multi_hop) {
        /* ipv6 link-local should be single-hop */
        ERRLOG("IPv6 link-local src/dest requires single-hop\n");
        err = 1;
    } else if (!p->multi_hop && !strlen(new_parms->port_name)) {
        /* single-hop needs port */
        ERRLOG("single-hop session requires port\n");
        err = 1;
    } else if (!strlen(new_parms->client.name) ||
               !strcmp(new_parms->client.name, CLIENT_NAME_DFLT)) {
        ERRLOG("Illegal client name %s\n", new_parms->client.name);
        err = 1;
    } else if (!new_parms->client.seqid) {
        ERRLOG("Illegal client seqid %d\n", new_parms->client.seqid);
        err = 1;
    }

    if (err) {
        /* sanity failed */
        free(new_parms);
        return PTM_CMD_ERROR;
    }

    /* check if param was previously supplied */
    memset(&key, 0x00, sizeof(key));
    strcpy(key.client_name, new_parms->client.name);
    if (!p->multi_hop)
        strcpy(key.port_vrf_name, new_parms->port_name);
    else
        strcpy(key.port_vrf_name, new_parms->parms.vrf_name);
    strcpy(key.dst_ipaddr, p->dst_ipaddr);
    HASH_FIND(ciph, sess_parm_hash, &key, sizeof(key), curr_parms);

    /* sanity check against all sess parms for this peer */
    for (i = 0; i < MAX_CLIENTS; i++) {

        ptm_bfd_client_t *cl = _get_client_info_by_idx(i);
        bfd_sess_parms *sp;
        parm_key tkey;

        if (!cl)
            continue;

        memset(&tkey, 0x00, sizeof(key));
        strcpy(tkey.client_name, cl->name);
        if (!p->multi_hop)
            strcpy(tkey.port_vrf_name, new_parms->port_name);
        else
            strcpy(tkey.port_vrf_name, new_parms->parms.vrf_name);
        strcpy(tkey.dst_ipaddr, p->dst_ipaddr);
        HASH_FIND(ciph, sess_parm_hash, &tkey, sizeof(tkey), sp);

        /* ignore vnid enabled parms */
        if (sp && !sp->parms.enable_vnid) {
            if (sp->parms.multi_hop != p->multi_hop) {
                ERRLOG("Client BFD type mismatch existing [%s:%s] != "
                        "new [%s:%s] session [%s]\n",
                        sp->client.name,
                        (sp->parms.multi_hop)?  "multihop":"singlehop",
                        new_parms->client.name,
                        (p->multi_hop)?"multihop":"singlehop",
                        p->dst_ipaddr);
                free(new_parms);
                return PTM_CMD_ERROR;
            }
        }
    } /* end for all clients */

    /* all checks have passed */

    if (!p->multi_hop && !p->enable_vnid) {
        ifindex = ptm_bfd_fetch_ifindex(new_parms->port_name,
                ptm_bfd.shop_sock);
        if (ifindex == -1) {
            free(new_parms);
            return PTM_CMD_ERROR;
        }
        new_parms->ifindex = ifindex;
        ptm_bfd_fetch_local_mac(new_parms->port_name,
                ptm_bfd.shop_sock, new_parms->local_mac);
    }

    bfd_client = _get_client_info_by_name(new_parms->client.name);
    if (!bfd_client) {
        bfd_client = _add_client_info(new_parms->client.name,
                                new_parms->client.seqid);
        if (!bfd_client) {
            ERRLOG("%s: Reached max BFD clients, can't add client [%s]\n",
                    __FUNCTION__, new_parms->client.name);
            free(new_parms);
            return PTM_CMD_ERROR;
        }
    }

    if (curr_parms) {
        ev = EVENT_UPD;
        memcpy(&curr_parms->parms, &new_parms->parms,
               sizeof(new_parms->parms));
        curr_parms->client.seqid = new_parms->client.seqid;
    } else {
        /* add the new param */
        memcpy(&new_parms->key, &key, sizeof(key));
        HASH_ADD(ciph, sess_parm_hash, key, sizeof(new_parms->key), new_parms);

        /* mark as pending */
        new_parms->pend = TRUE;
        new_parms->pend_ev = ev;
        _incr_client_num_sessions(new_parms->client.name, 1);

        ptm_bfd_start_sess_pend_timer();

        INFOLOG("Client PEND BFD [%s:%s] session [%s]\n",
            new_parms->client.name,
            (p->multi_hop)?"multihop":"singlehop",
            p->dst_ipaddr);
    }

    /* update client info */
    if (bfd_client->seqid != new_parms->client.seqid) {
        bfd_client->seqid = new_parms->client.seqid;
        /* start the client timer to clean up stale entries */
        ptm_bfd_start_client_timer();
    } else {
        /* extend the timer if present */
        ptm_bfd_extend_client_timer();
    }

    ptm_conf_ctl_cmd_status (client, in_ctxt, "pass", "Command Success");

    if (curr_parms) {
        free(new_parms);
    }

    return PTM_CMD_OK;
}

int
ptm_bfd_stop_client_sess(ptm_client_t *client, void *in_ctxt, char *errstr)
{
    bfd_sess_parms *new_parms, *curr_parms;
    ptm_bfd_client_t *bfd_client;
    int err = 0;
    parm_key key;

    DLOG("stop bfd client session\n");

    sprintf(errstr, "Command failure");

    new_parms = ptm_parse_bfd_params(NULL, in_ctxt);

    if (!new_parms) {
        /* error parsing arguments */
        ERRLOG("error parsing bfd args\n");
        return PTM_CMD_ERROR;
    }

    /* sanity checks */
    if (!strlen(new_parms->parms.dst_ipaddr)) {
        /* remote IP is mandatory */
        ERRLOG("Remote/Dest IP NULL\n");
        err = 1;
    } else if (new_parms->parms.multi_hop &&
               !strlen(new_parms->parms.src_ipaddr)) {
        /* multi-hop needs src IP */
        ERRLOG("multihop session requires src-ip\n");
        err = 1;
    } else if (!strlen(new_parms->client.name) ||
               !strcmp(new_parms->client.name, CLIENT_NAME_DFLT)) {
        ERRLOG("Illegal client name %s\n", new_parms->client.name);
        err = 1;
    }

    if (err) {
        /* sanity failed */
        free(new_parms);
        return PTM_CMD_ERROR;
    }

    bfd_client = _get_client_info_by_name(new_parms->client.name);

    if (!bfd_client) {
        /* no client info found - ignore */
        INFOLOG("No bfd client info [%s]\n", new_parms->client.name);
        free(new_parms);
        return PTM_CMD_ERROR;
    }

    memset(&key, 0x00, sizeof(key));
    strcpy(key.client_name, new_parms->client.name);
    if (!new_parms->parms.multi_hop )
        strcpy(key.port_vrf_name, new_parms->port_name);
    else
        strcpy(key.port_vrf_name, new_parms->parms.vrf_name);
    strcpy(key.dst_ipaddr, new_parms->parms.dst_ipaddr);
    HASH_FIND(ciph, sess_parm_hash, &key, sizeof(key), curr_parms);

    if (!curr_parms) {
        INFOLOG("No bfd client session [%s:%s]\n",
                new_parms->client.name, new_parms->parms.dst_ipaddr);
        free(new_parms);
        return PTM_CMD_ERROR;
    }

    if (new_parms->parms.multi_hop != curr_parms->parms.multi_hop) {
        /* session type does not match - ignore delete */
        ERRLOG("Client BFD type mismatch existing [%s:%s] != "
               "new [%s:%s] session [%s]\n",
                curr_parms->client.name,
                (curr_parms->parms.multi_hop)?"multihop":"singlehop",
                new_parms->client.name,
                (new_parms->parms.multi_hop)?"multihop":"singlehop",
                new_parms->parms.dst_ipaddr);
        free(new_parms);
        return PTM_CMD_ERROR;
    }

    ptm_conf_ctl_cmd_status (client, in_ctxt, "pass", "Command Success");

    INFOLOG("Client DEL BFD [%s:%s] session [%s]\n",
            new_parms->client.name,
            new_parms->parms.multi_hop?"multihop":"singlehop",
            new_parms->parms.dst_ipaddr);

    /* stop the BFD session if possible */
    handle_bfd_event(BFD_MODULE, new_parms, EVENT_DEL);

    if (curr_parms->pend)
        _decr_client_num_sessions(curr_parms->client.name, 1);

    HASH_DELETE(ciph, sess_parm_hash, curr_parms);
    free(curr_parms);
    free(new_parms);

    return PTM_CMD_OK;
}

void *ptm_bfd_get_next_sess_iter(void *ptr)
{
    bfd_session *bfd = ptr;
    return ((!bfd)?session_hash:bfd->sh.next);
}

static void
ptm_bfd_client_timer(cl_timer_t *timer, void *context)
{
    bfd_sess_parms *cp, *cptmp;
    ptm_bfd_client_t *client;
    int keep_timer = FALSE;

    /* walk list of client sess parms and check for
     * stale client entries (seq-id mismatch)
     */
    HASH_ITER(ciph, sess_parm_hash, cp, cptmp) {
        client = _get_client_info_by_name(cp->client.name);
        if (!client || (client->seqid != cp->client.seqid)) {
            /* remove this client reference */
            INFOLOG("Client seqid mismatch [%s:%x] != curr [%s:%x] [%s]\n",
                    cp->client.name,
                    cp->client.seqid,
                    (client)?client->name:"N/A",
                    (client)?client->seqid:-1,
                    cp->parms.dst_ipaddr);
            handle_bfd_event(BFD_MODULE, cp, EVENT_DEL);
            HASH_DELETE(ciph, sess_parm_hash, cp);
            free(cp);
            keep_timer = TRUE;
        }
    } /* for all client sessions */

    if (!keep_timer)
        ptm_bfd_stop_client_timer();

    return;
}

static void
ptm_bfd_sess_pend_timer(cl_timer_t *timer, void *context)
{
    bfd_sess_parms *cp, *cptmp;
    int keep_timer = FALSE;
    int num_started = 0;

    INFOLOG("Client Pend timer TIMBEG - sess count %d\n", ptm_bfd.session_count);

    /* walk list of client sess parms and check for
     * pending client entries
     * start a few...
     */
    HASH_ITER(ciph, sess_parm_hash, cp, cptmp) {

        if (!cp->pend)
            continue;

        if (num_started > MAX_SESS_PEND_PER_LOOP)
            break;

        cp->pend = FALSE;
        keep_timer = TRUE;
        num_started++;

        INFOLOG("Client Start BFD [%s:%s] session [%s]\n",
            cp->client.name,
            (cp->parms.multi_hop)?"multihop":"singlehop",
            cp->parms.dst_ipaddr);

        handle_bfd_event(BFD_MODULE, cp, cp->pend_ev);

        _decr_client_num_sessions(cp->client.name, 1);

    } /* for all client sessions */

    INFOLOG("Client Pend timer TIMEND - sess count %d\n", ptm_bfd.session_count);

    if (!keep_timer)
        ptm_bfd_stop_sess_pend_timer();

    return;
}

static void ptm_bfd_stop_client_timer(void)
{
    if (ptm_bfd.client_timer) {
        cl_timer_destroy(ptm_bfd.client_timer);
        ptm_bfd.client_timer = NULL;
    }
}

static void
ptm_bfd_stop_sess_pend_timer(void)
{
    if (ptm_bfd.sess_pend_timer) {
        cl_timer_destroy(ptm_bfd.sess_pend_timer);
        ptm_bfd.sess_pend_timer = NULL;
    }
}

static void
ptm_bfd_start_sess_pend_timer(void)
{
    if (!ptm_bfd.sess_pend_timer) {
        ptm_bfd.sess_pend_timer = cl_timer_create();
        cl_timer_arm(ptm_bfd.sess_pend_timer, ptm_bfd_sess_pend_timer,
                     PTM_BFD_SESS_PEND_INTERVAL, T_UF_PERIODIC);
    }
}

static void
ptm_bfd_start_client_timer(void)
{
    if (!ptm_bfd.client_timer) {
        ptm_bfd.client_timer = cl_timer_create();
        cl_timer_arm(ptm_bfd.client_timer, ptm_bfd_client_timer,
                     PTM_BFD_CLIENT_SYNC_INTERVAL, T_UF_PERIODIC);
    }
}

static void
ptm_bfd_extend_client_timer(void)
{
    if (ptm_bfd.client_timer) {
        cl_timer_destroy(ptm_bfd.client_timer);
        ptm_bfd.client_timer = cl_timer_create();
        cl_timer_arm(ptm_bfd.client_timer, ptm_bfd_client_timer,
                     PTM_BFD_CLIENT_SYNC_INTERVAL, T_UF_PERIODIC);
    }
}

static void ptm_bfd_send_evt_TO(bfd_session *bfd)
{
    char *cmd;
    char *msgbuf = NULL;
    char peer_addr[INET6_ADDRSTRLEN];
    bfd_status_ctxt_t b_ctxt = {0};

    if (!BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_IGNORE)) {

        if ((cmd = malloc(CMD_SZ)) == NULL) {
            INFOLOG("%s cmd malloc failed for session %s\n", __FUNCTION__,
                        ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr));
        } else if ((msgbuf = malloc(CTL_MSG_SZ)) == NULL) {
            INFOLOG("%s msg buf malloc failed for session %s\n", __FUNCTION__,
                        ptm_ipaddr_net2str(&bfd->shop.peer, peer_addr));
        }

        b_ctxt.bfd = bfd;
        if (cmd && msgbuf)
            ptm_conf_notify_status_all_clients(&b_ctxt, msgbuf, CTL_MSG_SZ,
                                                BFD_MODULE);
        if (msgbuf)
            free(msgbuf);
        if (cmd)
            free(cmd);

    } else {
        BFD_UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_IGNORE);
    }

    BFD_UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_SEND_EVT_ACTIVE);
}

static void
ptm_parse_bfd_client_params(char *args, void *in_ctxt, ptm_bfd_client_t *client_info)
{
    int seqid;
    char in_args[MAX_ARGLEN];
    char val[MAXNAMELEN];

    if (!args && !in_ctxt) {
        ERRLOG("%s: NULL args\n", __FUNCTION__);
        return;
    }

    if (args && (!strlen(args) || (strlen(args) >= MAX_ARGLEN)))
        return;

    /* check for some client params */
    if (args)
        ptm_conf_find_key_val(CLIENT_NAME, in_args, val);
    else
        ptm_lib_find_key_in_msg(in_ctxt, CLIENT_NAME, val);

    if (strlen(val)) {
        /* found key/val */
        strcpy(client_info->name, val);
        INFOLOG("%s: Assigning client name = %s\n", __FUNCTION__, val);
    }

    if (args)
        ptm_conf_find_key_val(CLIENT_SEQ_ID, in_args, val);
    else
        ptm_lib_find_key_in_msg(in_ctxt, CLIENT_SEQ_ID, val);

    if (strlen(val)) {
        /* found key/val */
        seqid = ptm_conf_parse_ulong_parm(val);
        if (seqid > 0) {
            INFOLOG("%s: Assigning seqid = %d\n", __FUNCTION__, seqid);
            client_info->seqid = seqid;
        }
    }
}

int
ptm_bfd_reg_client_handler(ptm_client_t *client, void *in_ctxt, char *errstr)
{
    ptm_bfd_client_t *client_info, new_client_info;

    INFOLOG("Register bfd client\n");

    sprintf(errstr, "Command failure");

    memset(&new_client_info, 0, sizeof(new_client_info));
    ptm_parse_bfd_client_params(NULL, in_ctxt, &new_client_info);

    /* sanity checks */
    if (new_client_info.name[0] == '\0') {
        /* client name is mandatory */
        INFOLOG("client name missing in registration\n");
        return PTM_CMD_ERROR;
    }

    if (new_client_info.seqid == 0) {
        /* seq ID is mandatory */
        INFOLOG("client seq id is not given\n");
        return PTM_CMD_ERROR;
    }

    ptm_conf_ctl_cmd_status (client, in_ctxt, "pass", "Command Success");

    client_info = _get_client_info_by_name(new_client_info.name);

    if (!client_info) {
        client_info = _add_client_info(new_client_info.name, new_client_info.seqid);
        if (!client_info) {
            INFOLOG("%s: Reached max BFD clients, can't add new client\n",
                        __FUNCTION__);
            return PTM_CMD_ERROR;
        }
    } else {
        if (client_info->seqid != new_client_info.seqid) {
            client_info->seqid = new_client_info.seqid;
            /* start the client timer to clean up stale entries */
            ptm_bfd_start_client_timer();
        }
    }

    return PTM_CMD_OK;
}

static void
ptm_bfd_client_sess_del_all(ptm_bfd_client_t *del_client)
{
    bfd_sess_parms *cp, *cptmp;

    /* walk list of client sess parms and delete all the sessions
     * referencing the client.
     */
    HASH_ITER(ciph, sess_parm_hash, cp, cptmp) {
        if (!strcmp(del_client->name, cp->client.name)) {
            /* remove this client reference */
            handle_bfd_event(BFD_MODULE, cp, EVENT_DEL);
            HASH_DELETE(ciph, sess_parm_hash, cp);
            free(cp);
        }
    } /* for all client sessions */

    return;
}

int
ptm_bfd_dereg_client_handler(ptm_client_t *client, void *in_ctxt, char *errstr)
{
    ptm_bfd_client_t *curr_client_info, client_info;

    DLOG("Deregister bfd client\n");

    sprintf(errstr, "Command failure");

    memset(&client_info, 0, sizeof(client_info));
    ptm_parse_bfd_client_params(NULL, in_ctxt, &client_info);

    /* sanity checks */
    if (client_info.name[0] == '\0') {
        /* client name is mandatory */
        INFOLOG("client name missing in deregistration\n");
        return PTM_CMD_ERROR;
    }

    ptm_conf_ctl_cmd_status (client, in_ctxt, "pass", "Command Success");

    curr_client_info = _get_client_info_by_name(client_info.name);

    if (!curr_client_info) {
        INFOLOG("%s: Client %s has not been registered\n",
                    __FUNCTION__, client_info.name);
        return PTM_CMD_ERROR;
    } else {
        ptm_bfd_client_sess_del_all(curr_client_info);
    }

    return PTM_CMD_OK;
}

static int
ptm_bfd_get_vrf_name(char *port_name, char *vrf_name)
{
    struct bfd_iface *iface;
    struct bfd_vrf *vrf;

    if ((port_name == NULL) || (vrf_name == NULL)) {
        return -1;
    }

    HASH_FIND(ifh, iface_hash, port_name, strlen(port_name), iface);

    if (iface) {
        HASH_FIND(vh, vrf_hash, &iface->vrf_id, sizeof(iface->vrf_id), vrf);
        if (vrf) {
            strcpy(vrf_name, vrf->name);
            return 0;
        }
    }
    return -1;
}
