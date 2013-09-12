/* Copyright 2013 Cumulus Networks, LLC.  All rights reserved. */

#ifndef __PTMCONF__H
#define __PTMCONF__H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <graphviz/cgraph.h>
#include "hashtable.h"
#include "ptm_event.h"

#define MAC_ADDR_SIZE 6
#define MAX_PORTS 257		/* nearest prime */
#define MAX_NODES 1033		/* nearest prime */

extern const char const *PTM_CONF_DIR;
extern const char const *PTM_CONF_FILE;

typedef enum {
  PTM_HOST_ID_TYPE_UNKNOWN,
  PTM_HOST_ID_TYPE_NAME,
  PTM_HOST_ID_TYPE_IP,
} ptm_conf_host_id_type_t;

typedef enum {
  PTM_TOPO_STATE_PASS,
  PTM_TOPO_STATE_FAIL
} ptm_conf_topo_state_t;

#ifndef TRUE
#define TRUE                  1
#endif

#ifndef FALSE
#define FALSE                 0
#endif

struct ptm_conf_node {
  char node_name[MAXNAMELEN+1];
  char mgmt_ip_addr[INET6_ADDRSTRLEN+1];
  ptm_conf_host_id_type_t id_type;
  int  state;
  hash_table_t *ports;
};

struct ptm_conf_nbr {
  char sys_name[MAXNAMELEN+1];
  char port_name[IF_NAMESIZE+1];
  char mac_addr[MAC_ADDR_SIZE];

  char ip_addr[INET6_ADDRSTRLEN+1];
  char chassis_id[MAC_ADDR_SIZE];
  time_t last_change_time;
};

typedef enum {
  PTM_NBR_CMP_PORT,
  PTM_NBR_CMP_MAC,
  PTM_NBR_CMP_IP
} ptm_conf_nbr_cmp_attr_t;

typedef enum {
  PTM_NBR_NO_INFO,
  PTM_NBR_MATCH,
  PTM_NBR_MISMATCH,
} ptm_conf_nbr_oper_state_t;

typedef enum {
  PTM_NBR_IF_UP,
  PTM_NBR_IF_DOWN
} ptm_conf_if_oper_state_t;

struct ptm_conf_port {
  char port_name[IF_NAMESIZE+1];
  ptm_conf_if_oper_state_t if_oper_state;
  ptm_conf_topo_state_t topo_oper_state;
  ptm_conf_nbr_cmp_attr_t cmp_attr;
  struct ptm_conf_nbr admin;
  struct ptm_conf_nbr oper;
  char mac_addr[MAC_ADDR_SIZE];
  int num_transitions;
};

struct ptm_conf_network {
  char graph_file[MAXNAMELEN+1];
  hash_table_t *nodes;
  struct ptm_conf_node me;
  time_t last_access_time;
  time_t last_good_access_time;
};

/**
 * Function to initialize the CONF_MODULE in ptmd. Given the topology
 * file, it builds the graph and initializes the node/port table.
 */
int ptm_conf_init(ptm_globals_t *);

/**
 * Function invoked whenever there is an update from LLDP about an
 * interface/port and its connected entity.
 */
void ptm_conf_process_nbr_update(ptm_event_t *);

/**
 * Function invoked whenever there is a new (control) client connected
 * to ptmd that is interested in topology updates.
 */
void ptm_conf_process_new_client(ptm_event_t *);

/**
 * Function invoked when ptmd receives a signal to reparse the topology
 * file - usually when the topology file has been updated and the user
 * wants the new prescription reflected.
 */
int ptm_conf_reparse_topology();

/**
 * Function invoked to free up the associated memory on exit
 */
void ptm_conf_finish(void);

#endif
