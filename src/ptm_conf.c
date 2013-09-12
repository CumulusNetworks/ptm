/*********************************************************************
 * Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 *
 * Parse the ptm.conf file, perform topology validation and send
 * notification on topo pass, topo fail and interface down events.
 *
 */

#include "ptm_conf.h"
#include "log.h"
#include "ptm_ctl.h"
#include "ptm_msg.h"
#include "csv.h"
#include <sys/inotify.h>
#include <libgen.h>
#include <stdbool.h>

static struct ptm_conf_network topo;

typedef struct _ptm_conf_globals_t_ {
  Agraph_t      *graph;
  ptm_globals_t *ptmg;
  char          *hostname;
  char          *hostip;
  int           file_wd;
} ptm_conf_globals_t;

ptm_conf_globals_t ptm_conf;

typedef enum {
  PTM_CONF_EDGE_IN = 1,
  PTM_CONF_EDGE_OUT
} ptm_conf_edge_dir_t;

static char *HOST_ID_TYPE = "hostidtype";
static const char const *HOST_ID_TYPE_IP_STR = "ipaddr";
static const char const *HOST_ID_TYPE_NAME_STR = "hostname";

const char const *PTM_CONF_DIR = "/etc/cumulus/ptm.d";
const char const *PTM_CONF_FILE = "topology.dot";
const char const *PTM_TOPO_PASS_FILE = "if-topo-pass";
const char const *PTM_TOPO_FAIL_FILE = "if-topo-fail";
const char const *PTM_TOPO_IFDOWN_FILE = "if-down";
char *PTM_CONF_EOF_STR = "EOF\n";

#define PTM_CONF_MAX_CMDS 2
#define PTM_CONF_MAX_CMD_NAME_LEN 16

struct ptm_conf_cmd_hdlr {
  char cmd_name[PTM_CONF_MAX_CMD_NAME_LEN];
  void (*cmd_hdlr)(ptm_event_t *, struct ptm_conf_network *);
};

static int ptm_conf_read(struct ptm_conf_network *topo);
static int ptm_conf_check_match(struct ptm_conf_port *port);
static int ptm_conf_get_hostid_type(Agraph_t *g);
static int ptm_conf_add_node(struct ptm_conf_network *topo, int host_id_type,
			char *hostname, char *host_addr, int me);
static int ptm_conf_update_nbrs_from_graph(struct ptm_conf_network *topo,
					   Agraph_t *g,
					   struct ptm_conf_node *from);
static void ptm_conf_process_graph_entry (struct ptm_conf_network *topo,
					  Agnode_t *gnode, Agedge_t *edge,
					  ptm_conf_edge_dir_t direction,
					  struct ptm_conf_node *node);
static void ptm_conf_update_nbr_from_graph (struct ptm_conf_port *port,
					    Agedge_t *edge,
					    ptm_conf_edge_dir_t direction);
static void ptm_conf_topo_action (struct ptm_conf_port *port, bool run_script);
static void ptm_conf_notify_clients(struct ptm_conf_port *port);
static void ptm_conf_notify_client(struct ptm_conf_port *port,
				   ptm_client_t *client);
static int ptm_conf_gs_foreach_client_hdlr (void *data, void *client);
static int ptm_conf_ds_foreach_client_hdlr (void *data, void *client);
static void ptm_conf_process_client_query (ptm_event_t *,
					   struct ptm_conf_network *);
static void ptm_conf_handle_get_status (ptm_event_t *event,
					struct ptm_conf_network *topo);

static void ptm_conf_handle_dump_status (ptm_event_t *event,
					 struct ptm_conf_network *topo);
static void ptm_conf_encode_port_header (csv_t *csv);
static void ptm_conf_encode_port (csv_t *csv, struct ptm_conf_port *port);

static struct ptm_conf_cmd_hdlr ptm_conf_cmds[PTM_CONF_MAX_CMDS] = {
  {"get-status", ptm_conf_handle_get_status},
  {"dump-status", ptm_conf_handle_dump_status},
};

int
ptm_conf_init (ptm_globals_t *g)
{
  int status;

  ptm_conf_finish ();
  topo.graph_file[MAXNAMELEN] = '\0';
  strcpy(topo.graph_file, g->topo_file);

  ptm_conf.ptmg = g;
  ptm_conf.hostname = g->my_hostname;
  ptm_conf.hostip = g->my_mgmtip;

  status = ptm_conf_read(&topo);
  g->conf_init_done = true;
  g->hostname_changed = false;
  g->mgmt_ip_changed = false;
  return (status);
}

int
ptm_conf_reparse_topology ()
{
  int status;

  status = ptm_conf_read(&topo);

  /*
   * Call LLDP module's populate routine for a refresh of the real
   * physical map.
   */
  PTM_MODULE_POPULATECB(ptm_conf.ptmg, LLDP_MODULE)();
  return (status);
}


void
ptm_conf_process_nbr_update (ptm_event_t *event)
{
  struct ptm_conf_port *port = NULL;

  if (event == NULL) {
    ERRLOG("%s:Null event received\n", __func__);
    return;
  }


  if (event->module != LLDP_MODULE) {
    DLOG("%s: Ignoring non-LLDP event (module %d)\n", __func__,
	    event->module);
    return;
  }

  if (topo.me.ports == NULL) {
    DLOG("%s: Ignoring port update as no config exists\n", __func__);
    return;
  }

  if (!hash_table_find(topo.me.ports, event->liface,
		       strlen(event->liface), (void **)&port)) {
    ERRLOG("Port %s: Unable to find port\n", event->liface);
    return;
  }
  if (port) {
    if (event->type == EVENT_ADD) {
      DLOG("Port %s: Received update/add event\n", port->port_name);
      port->oper.sys_name[MAXNAMELEN] = '\0';
      strncpy(port->oper.sys_name, event->rname, MAXNAMELEN);
      port->oper.port_name[IF_NAMESIZE] = '\0';
      strncpy(port->oper.port_name, event->riface, IF_NAMESIZE);
      strncpy(port->oper.mac_addr, event->rmac, MAC_ADDR_SIZE);
      if (event->rv4addr != NULL)
	strncpy(port->oper.ip_addr, event->rv4addr, INET_ADDRSTRLEN);
      else if (event->rv6addr != NULL)
	strncpy(port->oper.ip_addr, event->rv4addr, INET6_ADDRSTRLEN);
      else
	port->oper.ip_addr[0] = '\0';
      port->if_oper_state = PTM_NBR_IF_UP;
    } else if (event->type == EVENT_DEL) {
      DLOG("Port %s: Received del event\n", port->port_name);
      port->if_oper_state = PTM_NBR_IF_DOWN;
    } else {
      DLOG("%s: Unknown event received for port %s\n", __FUNCTION__, port->port_name);
    }

    time(&port->oper.last_change_time);
    ptm_conf_check_match(port);
  }
}

void
ptm_conf_process_new_client (ptm_event_t *event)
{
  if (event == NULL) {
    ERRLOG("%s: Null event received\n", __func__);
    return;
  }

  if (event->module != CTL_MODULE) {
    DLOG("%s: Ignorning non-CTL event (module %d)\n", __func__,
	    event->module);
    return;
  }

  if (event->type == EVENT_ADD) {
    if (topo.me.ports != NULL) {
      ptm_conf_handle_get_status(event, &topo);
    } else {
      ptm_ctl_send(event->client, PTM_MSG_EOF_STR, PTM_MSG_EOF_LEN);
    }
  } else if (event->type == EVENT_UPD) {
    /* Process the client's query */
    ptm_conf_process_client_query(event, &topo);
  } else {
    DLOG("%s: Ignorning non-ADD/UPD event\n", __func__);
  }
}

static int
ptm_conf_check_match (struct ptm_conf_port *port)
{
  int result = FALSE;

  if ((port->if_oper_state == PTM_NBR_IF_DOWN) &&
      (port->topo_oper_state != PTM_NBR_NO_INFO)) {
    port->topo_oper_state = PTM_NBR_NO_INFO;
    ptm_conf_topo_action(port, TRUE);
    return(result);
  }

  switch (port->cmp_attr) {
  case PTM_NBR_CMP_PORT:
    if ((strcmp(port->admin.port_name, port->oper.port_name) == 0) &&
	(strcmp(port->admin.sys_name, port->oper.sys_name) == 0)) {
      if (port->topo_oper_state != PTM_NBR_MATCH) {
	port->topo_oper_state = PTM_NBR_MATCH;
	DLOG("Port %s correctly matched with remote node %s, port %s\n",
		port->port_name, port->oper.sys_name, port->oper.port_name);
	result = TRUE;
	ptm_conf_topo_action(port, TRUE);
      } else {
	INFOLOG("(DUP)Port %s correctly matched with remote node %s, port %s\n",
		port->port_name, port->oper.sys_name, port->oper.port_name);
      }
    } else {
      if (port->topo_oper_state != PTM_NBR_MISMATCH) {
	port->topo_oper_state = PTM_NBR_MISMATCH;
	ERRLOG("Port %s peer is not correct! Expected %s.%s, got %s.%s\n",
	       port->port_name,
	       port->admin.sys_name, port->admin.port_name,
	       port->oper.sys_name, port->oper.port_name);
	ptm_conf_topo_action(port, TRUE);
      } else {
 	ERRLOG("(DUP) Port %s peer is not correct! Expected %s.%s, got %s.%s\n",
	       port->port_name,
	       port->admin.sys_name, port->admin.port_name,
	       port->oper.sys_name, port->oper.port_name);
      }
    }
    break;
  default:
    ERRLOG("Non Portname compares not handled presently\n");
    break;
  }

  return(result);
}

static void
ptm_conf_topo_action (struct ptm_conf_port *port, bool run_script)
{
  char cmd[256];

  if (port != NULL) {
    if (port->topo_oper_state == PTM_NBR_MATCH) {
      ptm_conf_notify_clients(port);
      if (run_script) {
	sprintf(cmd, "%s/%s %s", PTM_CONF_DIR, PTM_TOPO_PASS_FILE, port->port_name);
	system(cmd);
      }
    } else if (port->topo_oper_state == PTM_NBR_MISMATCH) {
	ptm_conf_notify_clients(port);
	if (run_script) {
	  sprintf(cmd, "%s/%s %s", PTM_CONF_DIR, PTM_TOPO_FAIL_FILE, port->port_name);
	  system(cmd);
	}
    }
  }
}

static void
ptm_conf_notify_clients (struct ptm_conf_port *port)
{
  ptm_client_t *client;

  for (client = ptm_client_iter(); client;
       client = ptm_client_iter_next(client)) {
    ptm_conf_notify_client(port, client);
  }
}

static void
ptm_conf_notify_client (struct ptm_conf_port *port, ptm_client_t *client)
{
  csv_t *csv = NULL;
  csv_record_t *rec;
  char sndbuf[CTL_MESSAGE_SIZE];
  int buflen;

  if (!client || !port) {
    return;
  }

  if (PTM_CLIENT_DETAIL_MODE(client)) {
    csv = csv_init(csv, sndbuf, CTL_MESSAGE_SIZE);
    rec = ptm_msg_encode_header(csv, NULL, 0, PTM_VERSION);
    ptm_conf_encode_port_header(csv);
    ptm_conf_encode_port(csv, port);
    buflen = csvlen(csv);
    ptm_msg_encode_header(csv, rec, (buflen - PTM_MSG_HEADER_LENGTH),
			  PTM_VERSION);
  } else {
    sprintf(sndbuf, "%*s %4s\n", IF_NAMESIZE, port->port_name,
	    (port->topo_oper_state == PTM_NBR_MATCH) ? "pass" : "fail");
    buflen = strlen(sndbuf);
  }

  DLOG("Sending %s\n", sndbuf);
  ptm_ctl_send(client, sndbuf, buflen);

  if (PTM_CLIENT_DETAIL_MODE(client)) {
    csv_clean(csv);
    csv_free(csv);
  }
}

static void
ptm_conf_handle_get_status (ptm_event_t *event, struct ptm_conf_network *topo)
{
  if (topo && (topo->me.ports != NULL)) {
    PTM_RESET_CLIENT_DETAIL_MODE(event->client);
    hash_table_foreach(topo->me.ports,
		       ptm_conf_gs_foreach_client_hdlr, event->client);
  }
  if (event)
    ptm_ctl_send(event->client, PTM_MSG_EOF_STR, PTM_MSG_EOF_LEN);
}

static void
ptm_conf_handle_dump_status (ptm_event_t *event, struct ptm_conf_network *topo)
{
  if (topo && (topo->me.ports != NULL)) {
    PTM_SET_CLIENT_DETAIL_MODE(event->client);
    hash_table_foreach(topo->me.ports,
		       ptm_conf_ds_foreach_client_hdlr, event->client);
  }
  if (event)
    ptm_ctl_send(event->client, PTM_MSG_EOF_STR, PTM_MSG_EOF_LEN);
}

static int
ptm_conf_gs_foreach_client_hdlr (void *data, void *client)
{
  ptm_conf_notify_client ((struct ptm_conf_port *)data, (ptm_client_t *)client);
  return (0);
}

static int
ptm_conf_ds_foreach_client_hdlr (void *data, void *client)
{
  ptm_conf_notify_client ((struct ptm_conf_port *)data, (ptm_client_t *)client);
  return (0);
}

static void
ptm_conf_free_node (void *data)
{
  if (data)
    free (data);
}

static void
ptm_conf_encode_port_header (csv_t *csv)
{
  if (!csv) {
    return;
  }
  csv_encode(csv, 5, "port", "status", "expected nbr", "observed nbr", "last update");
}

static void
ptm_conf_encode_port (csv_t *csv,
		      struct ptm_conf_port *port)
{
  char obuf[256];
  char ebuf[256];
  char tbuf[32];
  char tmpbuf[8];
  time_t now;
  double elapsed;
  int days, hrs, mins;

  if (!csv || !port) {
    return;
  }

  sprintf(ebuf, "%s:%s", port->admin.sys_name, port->admin.port_name);
  if (port->topo_oper_state != PTM_NBR_NO_INFO)
    sprintf(obuf, "%s:%s", port->oper.sys_name, port->oper.port_name);
  else
    sprintf(obuf, "no-info");

  if (port->oper.last_change_time == 0)
    strcpy(tbuf, "Nada");
  else {
    time(&now);
    elapsed = difftime(now, port->oper.last_change_time);

    tbuf[0] = '\0';
    if (elapsed > (24*3600)) {
      days = elapsed/(24*3600);
      elapsed -= (days*24*3600);
      sprintf(tmpbuf, "%dd:", days);
      strcat(tbuf, tmpbuf);
    }
    if (elapsed > 3600) {
      hrs = elapsed/3600;
      elapsed -= (hrs*3600);
      sprintf(tmpbuf, "%dh:", hrs);
      strcat(tbuf, tmpbuf);
    }
    if (elapsed > 60) {
      mins = elapsed/60;
      sprintf(tmpbuf, "%2dm:", mins);
      strcat(tbuf, tmpbuf);
      elapsed -= (mins*60);
    }

    sprintf(tmpbuf, "%2ds", (int)elapsed);
    strcat(tbuf, tmpbuf);
  }
  csv_encode(csv, 5, port->port_name,
	     ((port->topo_oper_state == PTM_NBR_MATCH) ? "pass" : "fail"),
	     ebuf, obuf, tbuf);

}

static void
ptm_conf_process_client_query(ptm_event_t *event, struct ptm_conf_network *topo)
{
  int cmd_num;

  if (!event || !topo) {
    return;
  }

  for (cmd_num = 0; cmd_num < PTM_CONF_MAX_CMDS; cmd_num++) {
    if (strncmp(ptm_conf_cmds[cmd_num].cmd_name, event->client->inbuf,
		strlen(ptm_conf_cmds[cmd_num].cmd_name)) == 0) {
      ptm_conf_cmds[cmd_num].cmd_hdlr(event, topo);
      return;
    }
  }
  ERRLOG("%s: Unknown command %s received from client fd %d\n",
	 __func__, event->client->inbuf, event->client->fd);
}

static int
ptm_conf_read (struct ptm_conf_network *topo)
{
  Agraph_t *g;
  char my_hostname[HOST_NAME_MAX];
  int id_type = PTM_HOST_ID_TYPE_NAME;
  FILE *filestream;
  int status;

  if (topo == NULL) {
    /* XX: Log error */
    return (-1);
  }

  filestream = fopen(topo->graph_file, "r");
  if (filestream == NULL) {
    ERRLOG ("File Open fail! %s, errno=%d\n", topo->graph_file, errno);
    return (-1);
  }
  if (ptm_conf.graph != NULL) {
    agclose(ptm_conf.graph);
    ptm_conf.graph = NULL;
  }
  g = agread(filestream, NIL(Agdisc_t *));

  if (g == NULL) {
    ERRLOG ("agread/agconcat failed (%s)\n", aglasterr());
    fclose(filestream);
    return (-1);
  }
  ptm_conf.graph = g;

  fclose(filestream);
  /* How do I know who I am ? IP Addr or name ? */
  id_type = ptm_conf_get_hostid_type (g);

  switch (id_type) {
  case PTM_HOST_ID_TYPE_NAME:
    if (gethostname(my_hostname, HOST_NAME_MAX)) {
      /* XX: Log error */
      ERRLOG ("Unable to retrieve hostname, error = %d\n", errno);
      return (-1);
    }
    if (ptm_conf.hostname) free(ptm_conf.hostname);
    ptm_conf.hostname = strdup(my_hostname);
    break;
  case PTM_HOST_ID_TYPE_IP:
    if (ptm_conf.hostip == NULL) {
      /* XX: Log error */
      ERRLOG ("Unable to retrieve host ip, error = %d\n", errno);
      return (-1);
    }
    break;
  default:
    /* XX: Log error */
    ERRLOG ("idtype %d not supported\n", id_type);
    return (-1);
    break;
  }

  /* Add info about myself */
  ptm_conf_add_node (topo, id_type, ptm_conf.hostname, ptm_conf.hostip, TRUE);

  /* Fill in the topo data structure */
  status = ptm_conf_update_nbrs_from_graph(topo, g, &(topo->me));

  return (status);
}

static int
ptm_conf_get_hostid_type (Agraph_t *g)
{
  char *id_attr;
  int id_type = PTM_HOST_ID_TYPE_NAME;

  id_attr = agget(g, HOST_ID_TYPE);
  if (id_attr != NULL) {
    if (strcmp (id_attr, HOST_ID_TYPE_IP_STR) == 0)
      id_type = PTM_HOST_ID_TYPE_IP;
    else if (strcmp (id_attr, HOST_ID_TYPE_NAME_STR) == 0)
      id_type = PTM_HOST_ID_TYPE_NAME;
    else
      id_type = PTM_HOST_ID_TYPE_UNKNOWN;
  }

  return (id_type);
}

static int
ptm_conf_add_node (struct ptm_conf_network *topo, int host_id_type,
		   char *hostname, char *host_addr, int me)
{
  if (me) {
    if (hostname != NULL) {
      topo->me.node_name[MAXNAMELEN] = '\0';
      strncpy(topo->me.node_name, hostname, MAXNAMELEN);
    }

    if (host_addr != NULL) {
      strncpy(topo->me.mgmt_ip_addr, host_addr,
	      INET6_ADDRSTRLEN);
      topo->me.mgmt_ip_addr[INET6_ADDRSTRLEN] = '\0';
    }

    topo->me.id_type = host_id_type;
  } else {
    if (topo->nodes == NULL) {
      topo->nodes = hash_table_alloc (MAX_NODES);
      if (topo->nodes == NULL) {
	ERRLOG ("Malloc Fail! Unable to allocate node hash table\n");
	return (1);
      }
    }
  }
  return (0);
}

static struct ptm_conf_port *
ptm_conf_add_port (struct ptm_conf_network *topo, struct ptm_conf_node *node,
		   char *portname, char *mac_addr,
		   ptm_conf_nbr_cmp_attr_t cmp_type)
{
  char *key;
  int keylen;
  struct ptm_conf_port *hport = NULL;

  assert (topo != NULL);
  assert (node != NULL);

  key = (cmp_type == PTM_NBR_CMP_PORT ? portname : mac_addr);
  keylen = (cmp_type == PTM_NBR_CMP_PORT ? strlen(key) : MAC_ADDR_SIZE);
  assert (keylen != 0);

  if (node->ports == NULL) {
    node->ports = hash_table_alloc(MAX_PORTS);
    if (node->ports == NULL) {
      ERRLOG ("Malloc Fail! Unable to allocate port hash table for %s\n",
	      node->node_name);
      return (NULL);
    }
  }

  if (hash_table_find (node->ports, key, keylen, (void **)&hport)) {
    ERRLOG ("Duplicate! Entry for port %s already exists. Updating\n",
	    key);
  } else {
    hport = (struct ptm_conf_port *)calloc(1, sizeof(struct ptm_conf_port));
    if (hport == NULL) {
      ERRLOG ("Malloc Fail! Unable to allocate ptm_conf_nbr structure for port %s of node %s\n",
	      key, node->node_name);
      return (NULL);
    }
    switch (cmp_type) {
    case PTM_NBR_CMP_PORT:
      hport->port_name[IF_NAMESIZE] = '\0';
      strncpy (hport->port_name, portname, MAXNAMELEN);
      break;
    case PTM_NBR_CMP_MAC:
      hport->port_name[0] = '\0';
      strncpy (hport->mac_addr, mac_addr, MAC_ADDR_SIZE);
      break;
    default:
      ERRLOG ("Unrecognized port type %d in node %s\n", cmp_type, node->node_name);
      break;
    }

    hport->cmp_attr = cmp_type;
    hash_table_add (node->ports, hport->port_name, keylen, hport);
  }

  return (hport);
}

static int
ptm_conf_update_nbrs_from_graph (struct ptm_conf_network *topo, Agraph_t *g,
				 struct ptm_conf_node *node)
{
  Agnode_t *gnode;
  Agedge_t *edge;

  /* XX: Handle IP addr based names later */
  assert(node->node_name[0] != '\0');
  gnode = agnode(g, node->node_name, FALSE);
  if (gnode == NULL) {
    ERRLOG ("Unable to find node %s in graph\n", node->node_name);
    return (1);
  }

  for (edge = agfstin(g, gnode); edge; edge = agnxtin(g, edge)) {
    ptm_conf_process_graph_entry(topo, gnode, edge, PTM_CONF_EDGE_IN, node);
  }

  for (edge = agfstout(g, gnode); edge; edge = agnxtout(g, edge)) {
    ptm_conf_process_graph_entry(topo, gnode, edge, PTM_CONF_EDGE_OUT, node);
  }
  return (0);
}

static void
ptm_conf_process_graph_entry (struct ptm_conf_network *topo, Agnode_t *gnode,
			      Agedge_t *edge, ptm_conf_edge_dir_t direction,
			      struct ptm_conf_node *node)
{
  char *ournode, *ourport;
  struct ptm_conf_port *hport;

  if (direction == PTM_CONF_EDGE_IN) {
    ournode = agnameof(aghead(edge));
    ourport = agget(edge, "headport");
  } else {
    ournode = agnameof(agtail(edge));
    ourport = agget(edge, "tailport");
  }

  if (strcmp(node->node_name, ournode) != 0) {
    ERRLOG ("Something's wrong! graph node %s is not us(%s)\n",
	    ournode, node->node_name);
    return;
  }

  /* XX: Add support for MAC addresses later */
  hport = ptm_conf_add_port(topo, node, ourport, NULL, PTM_NBR_CMP_PORT);
  if (hport == NULL)
    return;

  /* XX: Get iface oper state later. Not really needed */
  ptm_conf_update_nbr_from_graph(hport, edge, direction);
}

static void
ptm_conf_update_nbr_from_graph (struct ptm_conf_port *port, Agedge_t *edge,
				ptm_conf_edge_dir_t direction)
{
  char *nbrnode, *nbrport;
  char *cmp_type_str;
  ptm_conf_nbr_cmp_attr_t type;

  assert (port != NULL);
  assert (edge != NULL);

  if (direction == PTM_CONF_EDGE_IN) {
    nbrnode = agnameof(agtail(edge));
    nbrport = agget(edge, "tailport");
  } else {
    nbrnode = agnameof(aghead(edge));
    nbrport = agget(edge, "headport");
  }

  cmp_type_str = agget(edge, "compare");

  if (cmp_type_str == NULL)
    type = PTM_NBR_CMP_PORT;
  else if (strcmp(cmp_type_str, "macaddr") == 0)
    type = PTM_NBR_CMP_MAC;
  else {
    ERRLOG ("Unknown Port Compare Type: %s, defaulting to port\n",
	    cmp_type_str);
    type = PTM_NBR_CMP_PORT;
  }

  port->cmp_attr = type;
  port->admin.sys_name[MAXNAMELEN] = '\0';
  strncpy(port->admin.sys_name, nbrnode, MAXNAMELEN);

  port->admin.port_name[IF_NAMESIZE] = '\0';
  strncpy(port->admin.port_name, nbrport, MAXNAMELEN);

  time(&port->admin.last_change_time);
}

void
ptm_conf_finish (void)
{

  if (topo.me.ports != NULL) {
    hash_table_free(topo.me.ports, ptm_conf_free_node);
    topo.me.ports = NULL;
  }

  if (topo.nodes != NULL) {
    assert (topo.nodes != NULL);
  }

  if (ptm_conf.graph) {
    agclose(ptm_conf.graph);
    ptm_conf.graph = NULL;
  }

  if (ptm_conf.ptmg)
    ptm_conf.ptmg->conf_init_done = false;
}

#if 0
static void ptm_conf_init_watch ();
static void ptm_conf_add_watch ();
static void ptm_conf_remove_watch ();

int
ptm_conf_process_file_event (int fd, ptm_sockevent_e t, void *data)
{
#define EVENT_SIZE  (sizeof (struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))

  char buf[BUF_LEN];
  int len, i = 0;
  int file_changed = 0;
  int status = 0;

  len = read(fd, buf, BUF_LEN);
  if (len < 0) {
    if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      return (status);
    } else {
      ERRLOG("inotify read error (%s)\n", strerror(errno));
      return (-1);
    }
  }

  while (i < len) {
    struct inotify_event *event;

    event = (struct inotify_event *) &buf[i];

    /*
     * We are only interested in MODIFY events that include the file name
     * and the file name should match the topology file.
     */
    if ((event->mask & IN_MODIFY) && event->len &&
	(strcmp(event->name, topo.graph_file) == 0)) {
      DLOG("topo file changed\n");
      file_changed = 1;
      break;
    } else {
      DLOG("ptm_conf recvd (unwanted) inotify event %u\n", event->mask);
    }

    i += (EVENT_SIZE + event->len);
  }

  if (file_changed) {

    /*
     * Remove the watch for a bit since we open the file for building
     * the graph. Add it back when done with the parsing.
     */
    ptm_conf_remove_watch();
    ptm_conf_reparse_topology();
    ptm_conf_add_watch();
  }
  return (status);
}

static void
ptm_conf_add_watch ()
{
  char *dirc, *dir;
  int wd;

  dirc = strdup(topo.graph_file);
  dir = dirname(dirc);
  DLOG("adding watch for %s\n", dir);
  wd = inotify_add_watch(PTM_MODULE_FD(ptm_conf.ptmg, CONF_MODULE), dir,
			 (IN_MODIFY | IN_MOVE));
  if (wd < 0) {
    ERRLOG("inotify_add_watch error (%s)\n", strerror(errno));
    return;
  }
}

static void
ptm_conf_remove_watch ()
{
  int rc;

  DLOG("removing watch\n");
  rc = inotify_rm_watch(PTM_MODULE_FD(ptm_conf.ptmg, CONF_MODULE),
			ptm_conf.file_wd);
  if (rc < 0) {
    ERRLOG("inotify_rm_watch error (%s)\n", strerror(errno));
    return;
  }
}

static void
ptm_conf_init_watch ()
{
  int fd;

  fd = inotify_init1(IN_NONBLOCK);
  if (fd < 0) {
    ERRLOG("inotify_init error (%s)\n", strerror(errno));
    return;
  }
  PTM_MODULE_SET_FD(ptm_conf.ptmg, fd, CONF_MODULE);
}
#endif
