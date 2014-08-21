/* Copyright 2013 Cumulus Networks, Inc.  All rights reserved. */

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
#include "cgraph.h"
#include "hash/uthash.h"
#include "ptm_event.h"

#define MAC_ADDR_SIZE 6
#define MAX_PORTS 257		/* nearest prime */
#define MAX_NODES 1033		/* nearest prime */
#define MAX_ARGLEN 512

#define CTL_MSG_SZ 4096

#define EOF_SZ 4
#define CMD_SZ 256

typedef enum {
    PTM_CMD_UNKNOWN,
    PTM_CMD_OK,
    PTM_CMD_ERROR,
    PTM_CMD_MAX = PTM_CMD_ERROR,
} ptm_cmd_rval;

extern const char const *PTM_CONF_DIR;
extern const char const *PTM_CONF_FILE;
extern const char const *PTM_PIDFILE;
extern const char const *PTM_LOGFILE;

typedef enum {
  PTM_HOST_ID_TYPE_UNKNOWN,
  PTM_HOST_ID_TYPE_NAME,
  PTM_HOST_ID_TYPE_IP,
} ptm_conf_host_id_type_t;

typedef enum {
  PTM_TOPO_STATE_NO_INFO,
  PTM_TOPO_STATE_PASS,
  PTM_TOPO_STATE_FAIL
} ptm_conf_topo_state_t;

#ifndef TRUE
#define TRUE                  1
#endif

#ifndef FALSE
#define FALSE                 0
#endif


struct ptm_conf_nbr {
  char sys_name[MAXNAMELEN+1];
  char port_ident[MAXNAMELEN+1]; /* could be port name or description */
  time_t last_change_time;
};

typedef enum {
  PTM_NBR_CMP_PORT,
  PTM_NBR_CMP_MAC,
  PTM_NBR_CMP_IP
} ptm_conf_nbr_cmp_attr_t;

typedef struct ptm_conf_port {
  char port_name[MAXNAMELEN+1];
  unsigned int en_mods;      /* bit vector for modules enabled on node */
  ptm_conf_topo_state_t topo_oper_state;
  ptm_conf_nbr_cmp_attr_t cmp_attr;
  struct ptm_conf_nbr admin;
  char mac_addr[MAC_ADDR_SIZE];
  int num_transitions;
  UT_hash_handle ph; /* UThash handle look up local ports */
  UT_hash_handle nh; /* UThash handle look up node ports */
} ptm_conf_port_t;

struct ptm_conf_node {
  char node_name[MAXNAMELEN+1];
  char mgmt_ip_addr[INET6_ADDRSTRLEN+1];
  ptm_conf_host_id_type_t id_type;
  int  state;
  struct ptm_conf_port *ports;
};

struct ptm_conf_network {
  char graph_file[MAXNAMELEN+1];
  struct ptm_conf_node *nodes;
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
 * Function to parse the graph and call module handlers
 */
int ptm_conf_reparse(ptm_globals_t *g);

/**
 * Function invoked whenever there is a new (control) client connected
 * to ptmd that is interested in topology updates.
 */
int ptm_conf_process_new_client(ptm_event_t *);

/**
 * Function invoked when ptmd receives a signal to reparse the topology
 * file - usually when the topology file has been updated and the user
 * wants the new prescription reflected.
 */
int ptm_conf_reparse_topology(ptm_globals_t *);

/**
 * Function invoked to free up the associated memory on exit
 */
void ptm_conf_finish(void);

/**
 * Get configured check parameters for a port 
 */
struct ptm_conf_port *ptm_conf_get_port(ptm_event_t *);
struct ptm_conf_port *ptm_conf_get_port_by_name(char *port_name);

/**
 * Check if module is enabled
 */
int ptm_conf_is_mod_enabled(struct ptm_conf_port *port, ptm_module_e mod);

/** 
 * Signal to listeners about change in topology 
 */
void ptm_conf_topo_action (struct ptm_conf_port *port, bool pass);

/**
 * process a client query
 */
void ptm_conf_process_client_query (ptm_event_t *);

/**
 * find key/val in attribute list of edge
 */
void ptm_conf_find_key_val(char *key_arg, char *args, char *val);

/**
 * find template attribute and return attribute list
 */
void ptm_conf_get_template_str(char *tmpl_key, char *tmpl_str);

#endif
