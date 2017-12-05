/* Copyright 2013,2015 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

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
#define MAX_ARGLEN 512

#define CTL_MSG_SZ  1024
#define CMD_SZ      CTL_MSG_SZ

typedef enum {
    PTM_CMD_UNKNOWN,
    PTM_CMD_OK,
    PTM_CMD_ERROR,
    PTM_CMD_MAX = PTM_CMD_ERROR,
} ptm_cmd_rval;

extern const char const *PTM_CONF_DIR;
extern const char const *PTM_CONF_FILE;
extern const char const *PTM_PIDFILE;

typedef enum {
  PTM_HOST_ID_TYPE_UNKNOWN,
  PTM_HOST_ID_TYPE_NAME,
  PTM_HOST_ID_TYPE_IP,
} ptm_conf_host_id_type_t;

typedef enum {
  PTM_HOST_NAME_TYPE_UNKNOWN,
  PTM_HOST_NAME_TYPE_HOSTNAME,
  PTM_HOST_NAME_TYPE_FQDN,
} ptm_conf_host_name_type_t;

typedef enum {
  PTM_TOPO_STATE_NO_INFO,
  PTM_TOPO_STATE_PASS,
  PTM_TOPO_STATE_FAIL
} ptm_conf_topo_state_t;

typedef enum {
  PTM_GET_STATUS_PORT,
  PTM_GET_STATUS_BFD,
  PTM_GET_STATUS_LLDP,
} ptm_conf_get_status_type;

#define PTM_ENV_VAR_PORT        "PTM_PORT"
#define PTM_ENV_VAR_CBLSTATUS   "PTM_CBL"
#define PTM_ENV_VAR_EXPNBR      "PTM_EXPNBR"
#define PTM_ENV_VAR_ACTNBR      "PTM_ACTNBR"
#define PTM_ENV_VAR_BFDSTATUS   "PTM_BFDSTATUS"
#define PTM_ENV_VAR_BFDPEER     "PTM_BFDPEER"
#define PTM_ENV_VAR_BFDLOCAL    "PTM_BFDLOCAL"
#define PTM_ENV_VAR_BFDTYPE     "PTM_BFDTYPE"
#define PTM_ENV_VAR_BFDDOWNDIAG "PTM_BFDDIAG"
#define PTM_ENV_VAR_BFDVRF      "PTM_BFDVRF"

#ifndef TRUE
#define TRUE                  1
#endif

#ifndef FALSE
#define FALSE                 0
#endif

typedef struct ptm_conf_port {
  char port_name[MAXNAMELEN+1];
  unsigned int en_mods;      /* bit vector for modules enabled on node */
  ptm_conf_topo_state_t topo_oper_state;
  char nbr_sysname[MAXNAMELEN+1];
  char nbr_ident[MAXNAMELEN+1]; /* could be port name or description */
  char mac_addr[MAC_ADDR_SIZE];
  UT_hash_handle ph; /* UThash handle look up local ports */
} ptm_conf_port_t;

/**
 * Function to initialize the CONF_MODULE in ptmd. Given the topology
 * file, it builds the graph and initializes the node/port table.
 */
int ptm_conf_init(ptm_globals_t *);

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
void ptm_conf_topo_action (void *p_ctxt, bool pass);

/**
 * process a client cmd
 */
int ptm_conf_process_client_cmd (void *, void *);

/**
 * find key/val in attribute list of edge
 */
void ptm_conf_find_key_val(char *key_arg, char *args, char *val);

/**
 * find the next key/val in attribute list of edge
 */
void ptm_conf_find_next_key_val(char *args, char *key, char *val);

/**
 * find template attribute and return attribute list
 */
void ptm_conf_get_template_str(char *tmpl_key, char *tmpl_str);

/**
 * get the global hostname match type
 */
int ptm_conf_get_hostname_type (void);

/**
 * prune hostname from fqdn (if present)
 */
char *ptm_conf_prune_hostname(char *host_name);

/**
 * notify status to clients
 */
void ptm_conf_notify_status_all_clients(void *, char *, int, int);

/**
 * return ptm configuration path
 */
char *ptm_conf_get_conf_dir(void);

/**
 * send command status
 */
void ptm_conf_ctl_cmd_status (ptm_client_t *client, void *, char *, char *);

/**
 * ulong parse helper function
 */
int ptm_conf_parse_ulong_parm(char *val);

/**
 * msec parse helper function
 */
int ptm_conf_parse_msec_parm(char *val);

#endif
