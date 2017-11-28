/*********************************************************************
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#ifndef __PTMBFD__H
#define __PTMBFD__H

#include "hash/uthash.h"
#include "ptm_ipaddr.h"

/* forward declarations */
struct  bfd_sess_parms_s;

/**
 * List of type of listening socket Fds supported by BFD.
 * BFD_SHOP_FD: Single hop socket Fd
 * BFD_MHOP_FD: Multi hop socket Fd
 * BFD_ECHO_FD: Echo socket Fd
 * BFD_SHOP6_FD: Single hop IPv6 socket Fd
 * BFD_MHOP6_FD: Multi hop IPv6 socket Fd
 * BFD_MAX_FD: Max socket Fd
 */
typedef enum {
    BFD_SHOP_FD = 0,
    BFD_MHOP_FD,
    BFD_ECHO_FD,
    BFD_VXLAN_FD,
    BFD_SHOP6_FD,
    BFD_MHOP6_FD,
    BFD_MAX_FD
} bfd_fd_type_e;

typedef struct bfd_timers {
  uint32_t desired_min_tx;
  uint32_t required_min_rx;
  uint32_t required_min_echo;
} bfd_timers_t;

typedef struct bfd_discrs {
  uint32_t my_discr;
  uint32_t remote_discr;
} bfd_discrs_t;

/*
 * Format of control packet.  From section 4)
 */
typedef struct bfd_pkt_s {
  union {
    uint32_t byteFields;
    struct { uint8_t diag; uint8_t flags; uint8_t detect_mult; uint8_t len; };
  };
  bfd_discrs_t discrs;
  bfd_timers_t timers;
} bfd_pkt_t;

/*
 * Format of Echo packet.
 */
typedef struct bfd_echo_pkt_s {
  union {
    uint32_t byteFields;
    struct { uint8_t ver; uint8_t len; uint16_t reserved; };
  };
  uint32_t my_discr;
  uint8_t  pad[16];
} bfd_echo_pkt_t;


/* Macros for manipulating control packets */
#define BFD_VERMASK                   0x03
#define BFD_GETVER(diag)              ((diag >> 5) & BFD_VERMASK)
#define BFD_SETVER(diag, val)         ((diag) |= ( val & BFD_VERMASK) << 5)
#define BFD_VERSION                   1
#define BFD_PBIT                      0x20
#define BFD_FBIT                      0x10
#define BFD_CBIT                      0x08
#define BFD_ABIT                      0x04
#define BFD_DEMANDBIT                 0x02
#define BFD_DIAGNEIGHDOWN             3
#define BFD_DIAGDETECTTIME            1
#define BFD_DIAGADMINDOWN             7
#define BFD_SETDEMANDBIT(flags, val)  {if ((val)) flags |= BFD_DEMANDBIT;}
#define BFD_SETPBIT(flags, val)       {if ((val)) flags |= BFD_PBIT;}
#define BFD_GETPBIT(flags)            (flags & BFD_PBIT)
#define BFD_SETFBIT(flags, val)       {if ((val)) flags |= BFD_FBIT;}
#define BFD_GETFBIT(flags)            (flags & BFD_FBIT)
#define BFD_SETSTATE(flags, val)      {if ((val)) flags |= (val & 0x3) << 6;}
#define BFD_GETSTATE(flags)           ((flags >> 6) & 0x3)
#define BFD_ECHO_VERSION              1
#define BFD_ECHO_PKT_LEN              sizeof(bfd_echo_pkt_t)   /* Length of Echo packet */
#define BFD_CTRL_PKT_LEN              sizeof(bfd_pkt_t)
#define IP_HDR_LEN                    20
#define UDP_HDR_LEN                   8
#define ETH_HDR_LEN                   14
#define VXLAN_HDR_LEN                 8
#define BFD_ECHO_PKT_TOT_LEN          ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + BFD_ECHO_PKT_LEN
#define BFD_VXLAN_PKT_TOT_LEN         VXLAN_HDR_LEN + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + BFD_CTRL_PKT_LEN
#define BFD_RX_BUF_LEN                160

/* BFD session flags */
typedef enum ptm_bfd_session_flags {
  BFD_SESS_FLAG_NONE = 0,
  BFD_SESS_FLAG_ECHO = 1 << 0,        /* BFD Echo functionality */
  BFD_SESS_FLAG_ECHO_ACTIVE = 1 << 1, /* BFD Echo Packets are being sent
                                       * actively */
  BFD_SESS_FLAG_MH = 1 << 2,          /* BFD Multi-hop session */
  BFD_SESS_FLAG_VXLAN = 1 << 3,       /* BFD Multi-hop session which is
                                       * used to monitor vxlan tunnel */
  BFD_SESS_FLAG_IPV6 = 1 << 4,        /* BFD IPv6 session */
  BFD_SESS_FLAG_SEND_EVT_ACTIVE = 1 << 5, /* send event timer active */
  BFD_SESS_FLAG_SEND_EVT_IGNORE = 1 << 6, /* ignore send event when timer
                                           * expires */
} bfd_session_flags;

#define BFD_SET_FLAG(field, flag) (field |= flag)
#define BFD_UNSET_FLAG(field, flag) (field &= ~flag)
#define BFD_CHECK_FLAG(field, flag) (field & flag)

/* BFD session hash keys */
typedef struct ptm_bfd_shop_key {
  ptm_ipaddr peer;
  char port_name[MAXNAMELEN+1];
} bfd_shop_key;

typedef struct ptm_bfd_mhop_key {
  ptm_ipaddr peer;
  ptm_ipaddr local;
  char vrf_name[MAXNAMELEN+1];
} bfd_mhop_key;

typedef struct ptm_bfd_session_stats {
    uint64_t rx_ctrl_pkt;
    uint64_t tx_ctrl_pkt;
    uint64_t rx_echo_pkt;
    uint64_t tx_echo_pkt;
} bfd_session_stats_t;

typedef struct {
    uint32_t    seqid;
    char        name[MAXNAMELEN];
    uint32_t    num_sessions;
    uint32_t    num_pend_sessions;
} ptm_bfd_client_t;

typedef struct ptm_bfd_session_vxlan_info {
    uint32_t vnid;
    uint32_t decay_min_rx;
    uint8_t  forwarding_if_rx;
    uint8_t  cpath_down;
    uint8_t  check_tnl_key;
    uint8_t  local_dst_mac[6];
    uint8_t  peer_dst_mac[6];
    struct in_addr local_dst_ip;
    struct in_addr peer_dst_ip;
} bfd_session_vxlan_info_t;

/*
 * Session state information
 */
typedef struct ptm_bfd_session {

  /* protocol state per RFC 5880*/
  uint8_t ses_state;
  uint8_t remote_ses_state; /* unused unless demand mode is in effect */
  bfd_discrs_t discrs;
  uint8_t local_diag;
  uint8_t demand_mode;
  uint8_t remote_demand_mode;
  uint8_t detect_mult;
  uint8_t remote_detect_mult;
  uint8_t mh_ttl;

  /* Timers */
  bfd_timers_t timers;
  bfd_timers_t new_timers;
  uint32_t slow_min_tx;
  uint32_t up_min_tx;
  uint64_t detect_TO;
  struct timespec detect_timer;
  uint64_t xmt_TO;
  struct timespec xmt_timer;
  uint64_t echo_xmt_TO;
  struct timespec echo_xmt_timer;
  uint64_t echo_detect_TO;
  struct timespec echo_detect_timer;
  uint64_t send_evt_TO;
  struct timespec send_evt_timer;

  /* software object state */
  uint8_t curr_poll_seq;
  uint8_t polling;

  /* This and the localDiscr are the keys to state info */
  union {
    bfd_shop_key shop;
    bfd_mhop_key mhop;
  };
  int sock;

  /* sess parms that reference this session */
  struct  bfd_sess_parms_s *parm_hash;

  /* fields needed for uthash integration */
  UT_hash_handle sh; /* use session as key */
  union {
    UT_hash_handle ph; /* use peer and port as key */
    UT_hash_handle mh; /* use peer and local as key */
  };

  ptm_ipaddr local_ip;
  int   ifindex;
  uint8_t local_mac[6];
  uint8_t peer_mac[6];
  uint16_t src_udp_port;
  uint16_t ip_id;

  /* BFD session flags */
  bfd_session_flags flags;

  uint8_t echo_pkt[BFD_ECHO_PKT_TOT_LEN]; /* Save the Echo Packet
                                           * which will be transmitted */
  bfd_session_stats_t stats;
  bfd_session_vxlan_info_t vxlan_info;
  struct timespec up_time; /* last up time */
} bfd_session;

#define PTM_BFD_INVALID_VNID    (-1)

/**
 * List of IP address family supported by BFD session.
 * BFD_AFI_V4: Support only IPv4 peer sessions
 * BFD_AFI_V6: Support only IPv6 peer sessions
 * BFD_AFI_BOTH: Support both IPv4 and IPv6 peer sessions
 */
typedef enum bfd_afi_e {
    BFD_AFI_V4 = 1,
    BFD_AFI_V6,
    BFD_AFI_BOTH,
} bfd_afi;

typedef struct bfd_parms_list_s {
  uint32_t up_min_tx;
  uint32_t detect_mult;
  bfd_timers_t timers;
  uint32_t slow_min_tx;
  uint32_t mh_ttl;
  char src_ipaddr[INET6_ADDRSTRLEN+1];
  char dst_ipaddr[INET6_ADDRSTRLEN+1];
  char ifname[MAXNAMELEN+1];
  uint32_t vnid;
  uint32_t enable_vnid;
  uint32_t multi_hop;
  /* ovs schema 1.3 */
  uint8_t local_dst_mac[6];
  char local_dst_ip[INET_ADDRSTRLEN+1];
  uint8_t remote_dst_mac[6];
  char remote_dst_ip[INET_ADDRSTRLEN+1];
  uint32_t decay_min_rx;
  uint32_t forwarding_if_rx;
  uint32_t cpath_down;
  uint32_t check_tnl_key;
  bfd_afi  afi;
  uint32_t send_event;
  uint32_t echo_support;
  char vrf_name[MAXNAMELEN+1];
} bfd_parms_list;

typedef struct parm_key_s {
    char client_name[MAXNAMELEN+1];
    char port_vrf_name[MAXNAMELEN+1]; /* port name for single hop and
				       * vrf name for multi-hop */
    char dst_ipaddr[INET6_ADDRSTRLEN+1];
} parm_key;

typedef struct  bfd_sess_parms_s {

  char port_name[MAXNAMELEN+1];
  struct sockaddr_in *sin; /* for multi-hop use */
  int ifindex; /* ifindex of the local interface */
  uint8_t local_mac[6];
  int vxlan_sock;
  bfd_parms_list parms;
  ptm_bfd_client_t client;
  int pend;
  ptm_event_e pend_ev;
  /* fields needed for uthash integration */
  parm_key key;
  UT_hash_handle ph;   /* use port name as key */
  UT_hash_handle ciph; /* use client name+dst ip as key */
  UT_hash_handle ch;   /* use client name as key (per bfd sess) */
} bfd_sess_parms;

typedef struct bfd_diag_str_list_s {
    char *str;
    int type;
} bfd_diag_str_list;

typedef struct bfd_state_str_list_s {
    char *str;
    int type;
} bfd_state_str_list;

typedef struct _bfd_parms_key_s {
    char *key;
    int (*key_cb)(bfd_parms_list *, char *);
} bfd_parms_key;

typedef struct _bfd_status_ctxt_s {
    bfd_session     *bfd;
    int              set_env_var;
} bfd_status_ctxt_t;

struct bfd_vrf {
    int vrf_id;
    char name[MAXNAMELEN+1];
    UT_hash_handle vh;
} bfd_vrf;

struct bfd_iface {
    int vrf_id;
    char ifname[MAXNAMELEN+1];
    UT_hash_handle ifh;
} bfd_iface;

/* States defined per 4.1 */
#define PTM_BFD_ADM_DOWN   0
#define PTM_BFD_DOWN       1
#define PTM_BFD_INIT       2
#define PTM_BFD_UP         3


/* Various constants */
#define BFD_DEF_DEMAND             0
#define BFD_DEFDETECTMULT          3
#define BFD_DEFDESIREDMINTX        (300*MSEC_PER_SEC)
#define BFD_DEFREQUIREDMINRX       (300*MSEC_PER_SEC)
#define BFD_DEF_REQ_MIN_ECHO       (50*MSEC_PER_SEC)
#define BFD_DEF_SLOWTX             (2000*MSEC_PER_SEC)
#define BFD_DEF_MHOP_TTL           5
#define BFD_DEF_AFI                BFD_AFI_V4
#define BFD_DEF_SEND_EVT           0
#define BFD_DEF_ECHO_SUPPORT       0
#define BFD_MIN_REQ_MIN_ECHO       (50*MSEC_PER_SEC)
#define BFD_PKT_LEN                24         /* Length of control packet */
#define BFD_TTL_VAL                255
#define BFD_RCV_TTL_VAL            1
#define BFD_TOS_VAL                0xC0
#define BFD_PKT_INFO_VAL           1
#define BFD_IPV6_PKT_INFO_VAL      1
#define BFD_IPV6_ONLY_VAL          1
#define BFD_DOWNMINTX              (300*MSEC_PER_SEC)
#define BFD_SRCPORTINIT            49142
#define BFD_SRCPORTMAX             65536
#define BFD_DEFDESTPORT            3784
#define BFD_DEF_ECHO_PORT          3785
#define BFD_DEF_MHOP_DEST_PORT     4784
#define BFD_NULL_TIMER             -1
#define BFD_CMD_STRING_LEN         (MAXNAMELEN + 50)
#define BFD_BUFFER_LEN             (BFD_CMD_STRING_LEN + MAXNAMELEN + 1)

/* Function prototypes */
void ptm_bfd_rcv(int s, void *arg);
void ptm_bfd_snd(bfd_session *bfd, int fbit);
void ptm_bfd_detect_TO(bfd_session *bfd);
void ptm_bfd_ses_dn(bfd_session *bfd, uint8_t diag);
void ptm_bfd_ses_up(bfd_session *bfd);
void ptm_bfd_start_xmt(bfd_session *bfd);
void ptm_bfd_xmt_TO(bfd_session *bfd, int fbit);
void ptm_bfd_start_xmt_timer(bfd_session *bfd);
int ptm_init_bfd(ptm_globals_t *g);
int ptm_session_bfd(ptm_event_t *event);
int ptm_update_bfd(ptm_event_t *event);
int ptm_bfd_start_client_sess(ptm_client_t *client, void *, char *);
int ptm_bfd_stop_client_sess(ptm_client_t *client, void *, char *);
void *ptm_bfd_get_next_sess_iter(void *ptr);
int ptm_bfd_get_client_handler(ptm_client_t *client, void *, char *);
int ptm_bfd_reg_client_handler(ptm_client_t *client, void *, char *);
int ptm_bfd_dereg_client_handler(ptm_client_t *, void *, char *);

#endif /* __PTMBFD__H */
