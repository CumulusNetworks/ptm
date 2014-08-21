/* Copyright 2014 Cumulus Networks, Inc.  All rights reserved. */

#ifndef __PTMBFD__H
#define __PTMBFD__H

#include "hash/uthash.h"

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
#define BFD_DIAGNEIGHDOWN             (3 << 3)
#define BFD_DIAGDETECTTIME            (1 << 3)
#define BFD_DIAGADMINDOWN             (7 << 3)
#define BFD_SETDEMANDBIT(flags, val)  {if ((val)) flags |= BFD_DEMANDBIT;}
#define BFD_SETPBIT(flags, val)       {if ((val)) flags |= BFD_PBIT;}
#define BFD_SETFBIT(flags, val)       {if ((val)) flags |= BFD_FBIT;}
#define BFD_SETSTATE(flags, val)      {if ((val)) flags |= (val & 0x3) << 6;}
#define BFD_GETSTATE(flags)           ((flags >> 6) & 0x3)

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

  /* Timers */
  bfd_timers_t timers;
  uint32_t up_min_tx;
  uint64_t detect_TO;
  struct timespec detect_timer;
  uint64_t xmt_TO;
  struct timespec xmt_timer;

  /* software object state */
  uint8_t curr_poll_seq;
  uint8_t polling;

  /* This and the localDiscr are the keys to state info */
  struct in_addr peer;
  int sock;

  /* fields needed for ptm integration */
  ptm_event_t *nbr_ev;

  /* fields needed for uthash integration */
  UT_hash_handle sh; /* use session as key */
  UT_hash_handle ph; /* use peer as key */
} bfd_session;

typedef enum  {
    QUAGGA_PRI,
    NBR_PRI,
} bfdPtmPeerPriority;

typedef struct bfdParmsList_s {
  uint32_t up_min_tx;
  uint32_t detect_mult;
  bfd_timers_t timers;
  bfdPtmPeerPriority peer_pri;
} bfd_parm_list;

typedef struct  bfdPortParms_s {

  char port_name[MAXNAMELEN+1];
  struct sockaddr_in *sin; /* for multi-hop use */

  bfd_parm_list parms;

  /* fields needed for uthash integration */
  UT_hash_handle ph; /* use port as key */
} bfd_port_parms;

typedef struct BfdDiagStrList_s {
    char *str;
    int type;
} BfdDiagStrList;

typedef struct BfdStateStrList_s {
    char *str;
    int type;
} BfdStateStrList;

typedef struct PtmPeerPriList_s {
    char *str;
    bfdPtmPeerPriority type;
} PtmPeerPriList;

typedef struct _bfdParmsKey_s {
    char *key;
    int (*key_cb)(bfd_parm_list *, char *);
} bfdParmsKey;

typedef struct  bfdPendSession_s {

  char port_name[MAXNAMELEN+1];

  ptm_event_t *nbr_ev;

  /* fields needed for uthash integration */
  UT_hash_handle ph; /* use port as key */
} bfdPendSession;

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
#define BFD_PKT_LEN                24         /* Length of control packet */
#define BFD_TTL_VAL                255
#define BFD_RCV_TTL_VAL            1
#define BFD_TOS_VAL                0xC0
#define BFD_DOWNMINTX              (300*MSEC_PER_SEC)
#define BFD_SRCPORTINIT            49142
#define BFD_SRCPORTMAX             65536
#define BFD_DEFDESTPORT            3784
#define BFD_NULL_TIMER             -1

/* Function prototypes */
void ptm_bfd_rcv(int s, void *arg);
void ptm_bfd_snd(bfd_session *bfd, int fbit);
void ptm_bfd_detect_TO(bfd_session *bfd);
void ptm_bfd_ses_dn(bfd_session *bfd, uint8_t diag);
void ptm_bfd_ses_up(bfd_session *bfd);
void ptm_bfd_start_xmt(bfd_session *bfd);
void ptm_bfd_xmt_TO(bfd_session *bfd);
void ptm_bfd_start_xmt_timer(bfd_session *bfd);
int ptm_bfd_ses_del(bfd_session *bfd);
//int ptm_bfd_del_ses_list(bfd_session **list, bfd_session *bfd);
int ptm_init_bfd(ptm_globals_t *g);
int ptm_session_bfd(ptm_event_t *event);
//int ptm_process_bfd(int s, ptm_sockevent_e se, void *udata);
int ptm_update_bfd(ptm_event_t *event);

#endif /* __PTMBFD__H */
