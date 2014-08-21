/*********************************************************************
 * Copyright 2013 Cumulus Networks, Inc.  All rights reserved.
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
#include <strings.h>

static struct ptm_conf_network g_topo;

typedef struct _ptm_conf_globals_t_ {
    Agraph_t      *graph;
    ptm_globals_t *ptmg;
    char          *hostname;
    char          *hostip;
    int           file_wd;
    unsigned int  topo_retry_cnt;
} ptm_conf_globals_t;

ptm_conf_globals_t ptm_conf;

typedef enum {
    PTM_CONF_EDGE_IN = 1,
    PTM_CONF_EDGE_OUT
} ptm_conf_edge_dir_t;

static char *HOST_ID_TYPE = "hostidtype";
static const char const *HOST_ID_TYPE_IP_STR = "ipaddr";
static const char const *HOST_ID_TYPE_NAME_STR = "hostname";

char const *PTM_PIDFILE = "/var/run/ptmd.pid";
char const *PTM_LOGFILE = "/var/log/ptmd.log";
char const *PTM_CONF_DIR = "/etc/ptm.d";
char const *PTM_CONF_FILE = "topology.dot";
char const *PTM_TOPO_PASS_FILE = "if-topo-pass";
char const *PTM_TOPO_FAIL_FILE = "if-topo-fail";
char const *PTM_TOPO_IFDOWN_FILE = "if-down";

#define PTM_CONF_MAX_CMDS 16
#define TOPO_RETRY_DISPLAY_INTERVAL 5

struct ptm_conf_cmd_list {
    char *cmd_name;
    ptm_cmd_rval (* cmd_cb) (ptm_event_t *, char *);
};

static int ptm_conf_read(struct ptm_conf_network *topo);
static int ptm_conf_get_hostid_type(Agraph_t *g);
static int ptm_conf_add_node(struct ptm_conf_network *topo, int host_id_type,
                             char *hostname, char *host_addr, int me);
static int ptm_conf_parse_graph (struct ptm_conf_network *topo, Agraph_t *g,
				 struct ptm_conf_node *node, int reparse);
static void ptm_conf_process_graph_entry (struct ptm_conf_network *topo,
					  Agnode_t *gnode, Agedge_t *edge,
					  ptm_conf_edge_dir_t direction,
					  struct ptm_conf_node *node);
static void ptm_conf_update_nbr_from_graph (struct ptm_conf_port *port,
					    Agedge_t *edge,
					    ptm_conf_edge_dir_t direction);
static csv_t *ptm_conf_get_port_status(struct ptm_conf_port *port,
                                       char *incmd, char *ret_msg);
static void ptm_conf_notify_status_all_clients(struct ptm_conf_port *port,
                                               char *);
static ptm_cmd_rval ptm_conf_ctl_cmd_get_status (ptm_event_t *, char *);
static ptm_cmd_rval ptm_conf_ctl_cmd_get_debug (ptm_event_t *, char *);

static struct ptm_conf_cmd_list ptm_conf_cmds[PTM_CONF_MAX_CMDS] = {
    {   .cmd_name = "get-status", .cmd_cb = ptm_conf_ctl_cmd_get_status},
    {   .cmd_name = "get-debug", .cmd_cb = ptm_conf_ctl_cmd_get_debug},
    {   .cmd_name = NULL},
};

static inline char *
ptm_cmd_rval_string (ptm_cmd_rval rval)
{
    char *rvalstr[] = {"PTM_CMD_UNKNOWN", "PTM_CMD_OK", "PTM_CMD_ERROR"};
    if (rval < PTM_CMD_MAX) {
        return (rvalstr[rval]);
    }
    return ("null");
}

int
ptm_conf_init (ptm_globals_t *g)
{
    int status;

    g_topo.graph_file[MAXNAMELEN] = '\0';
    strcpy(g_topo.graph_file, g->topo_file);
    ptm_conf.ptmg = g;
    ptm_conf.hostname = g->my_hostname;
    ptm_conf.hostip = g->my_mgmtip;

    status = ptm_conf_read(&g_topo);
    if (!status) {
        g->conf_init_done = true;
        g->hostname_changed = false;
        g->mgmt_ip_changed = false;
    } else {
        ptm_conf_finish ();
    }
    return (status);
}

int
ptm_conf_reparse(ptm_globals_t *g)
{
    int status = -1;

    if (!ptm_conf.graph)
        return status;

    status = ptm_conf_parse_graph(&g_topo, ptm_conf.graph, &g_topo.me, TRUE);

    return (status);
}

void
ptm_conf_topo_action (struct ptm_conf_port *port, bool pass)
{
    char cmd[CMD_SZ];
    char msgbuf[CTL_MSG_SZ];

    if (pass) {
        ptm_conf_notify_status_all_clients(port, msgbuf);
        sprintf(cmd, "%s/%s \"%s \"&", PTM_CONF_DIR, PTM_TOPO_PASS_FILE,
                msgbuf);
        system(cmd);
    } else {
        ptm_conf_notify_status_all_clients(port, msgbuf);
        sprintf(cmd, "%s/%s \"%s \"&", PTM_CONF_DIR, PTM_TOPO_FAIL_FILE,
                msgbuf);
        system(cmd);
    }
}

static void
ptm_conf_notify_status_all_clients(struct ptm_conf_port *port, char *ret_msg)
{
    ptm_client_t *client, *save;
    csv_t *csv;

    csv = ptm_conf_get_port_status(port, "get-status", ret_msg);

    if (!csv)
        return;

    for (client = ptm_client_safe_iter(&save); client;
         client = ptm_client_safe_iter_next(&save)) {
        ptm_ctl_send(client, ret_msg, csvlen(csv));
        ptm_ctl_send(client, PTM_MSG_EOF_STR, PTM_MSG_EOF_LEN);
    }

    csv_clean(csv);
    csv_free(csv);
}

static csv_t *
ptm_conf_get_port_status(struct ptm_conf_port *port,
                         char *incmd,
                         char *ret_msg)
{
    csv_t *csv = NULL;
    csv_record_t *ptm_hrec;
    csv_record_t *mod_hrec, *tmp_hrec;
    csv_record_t *mod_drec, *tmp_drec;
    char localbuf[CTL_MSG_SZ];
    char *msgbuf = localbuf;
    int m;
    ptm_cmd_rval rval = PTM_CMD_OK;
    char cmdline[MAX_ARGLEN];
    char *opt = NULL;

    if (ret_msg)
        msgbuf = ret_msg;

    strcpy(cmdline, incmd);
    strtok_r(cmdline, " ", &opt);

    /* Initialize csv for using discrete record buffers */
    csv = csv_init(csv, NULL, CTL_MSG_SZ);
    ptm_hrec = ptm_msg_encode_header(csv, NULL, 0, PTM_VERSION);

    mod_hrec = mod_drec = NULL;

    for (m = 0; m < MAX_MODULE; m++ ) {
        if (PTM_MODULE_STATUSCB(ptm_conf.ptmg, m)) {
            rval = PTM_MODULE_STATUSCB(ptm_conf.ptmg, m)(csv,
                        &tmp_hrec, &tmp_drec, opt, port);

            if (rval != PTM_CMD_OK) {
                ERRLOG("status_cb module %s rval %s\n",
                       ptm_module_string(m), ptm_cmd_rval_string(rval));
                break;
            }

            /* concat the records returned by each module */
            if (mod_hrec)
                mod_hrec = csv_concat_record(csv, mod_hrec, tmp_hrec);
            else
                mod_hrec = tmp_hrec;

            if (mod_drec)
                mod_drec = csv_concat_record(csv, mod_drec, tmp_drec);
            else
                mod_drec = tmp_drec;

            if (csvlen(csv) > CTL_MSG_SZ) {
                /* should not happen !! */
                ERRLOG("%s: Exceeded message buffer\n", __FUNCTION__);
                break;
            }
        }
    }

    /* wrap up csv */
    ptm_msg_encode_header(csv, ptm_hrec, (csvlen(csv) - PTM_MSG_HEADER_LENGTH),
                          PTM_VERSION);

    /* parse csv contents into string */
    csv_serialize(csv, msgbuf);

    if (rval != PTM_CMD_OK) {
        csv_clean(csv);
        csv_free(csv);
        csv = NULL;
    }

    return csv;
}

static void ptm_conf_ctl_cmd_error (ptm_event_t *event, char *errstr)
{
    csv_t *csv = NULL;
    csv_record_t *rec;
    char msgbuf[CTL_MSG_SZ];
    int buflen = 0;

    csv = csv_init(csv, msgbuf, CTL_MSG_SZ);
    rec = ptm_msg_encode_header(csv, NULL, 0, PTM_VERSION);

    /* first the header */
    csv_encode(csv, 2, "cmd", "error");

    /* now the data */
    csv_encode(csv, 2, event->client->inbuf, errstr);

    /* wrap up csv */
    buflen = csvlen(csv);
    ptm_msg_encode_header(csv, rec, (buflen - PTM_MSG_HEADER_LENGTH),
                          PTM_VERSION);

    DLOG("Sending %s\n", msgbuf);
    ptm_ctl_send(event->client, msgbuf, buflen);

    csv_clean(csv);
    csv_free(csv);

    ptm_ctl_send(event->client, PTM_MSG_EOF_STR, PTM_MSG_EOF_LEN);
}

static void ptm_conf_ctl_cmd_unknown (ptm_event_t *event, char *arg)
{
    csv_t *csv = NULL;
    csv_record_t *rec;
    char msgbuf[CTL_MSG_SZ];
    int buflen = 0;

    csv = csv_init(csv, msgbuf, CTL_MSG_SZ);
    rec = ptm_msg_encode_header(csv, NULL, 0, PTM_VERSION);

    /* first the header */
    csv_encode(csv, 2, "cmd", "status");

    /* now the data */
    csv_encode(csv, 2, arg, "Unsupported command");

    /* wrap up csv */
    buflen = csvlen(csv);
    ptm_msg_encode_header(csv, rec, (buflen - PTM_MSG_HEADER_LENGTH),
                          PTM_VERSION);

    DLOG("Sending %s\n", msgbuf);
    ptm_ctl_send(event->client, msgbuf, buflen);

    csv_clean(csv);
    csv_free(csv);

    ptm_ctl_send(event->client, PTM_MSG_EOF_STR, PTM_MSG_EOF_LEN);
}

static ptm_cmd_rval
ptm_conf_ctl_cmd_get_debug (ptm_event_t *event, char *args)
{
    ptm_module_e m;
    ptm_cmd_rval rval;
    char *modstr;
    int found = 0;
    csv_t *csv = NULL;
    csv_record_t *ptm_hrec;
    char msgbuf[CTL_MSG_SZ];
    char errstr[CTL_MSG_SZ];

    if (!ptm_conf.graph) {
        sprintf(errstr,
            "No valid topology file. Check %s/%s",
            PTM_CONF_DIR, PTM_CONF_FILE);
        ptm_conf_ctl_cmd_error (event, errstr);
        return PTM_CMD_OK;
    }

    if (!g_topo.me.ports) {
        sprintf(errstr,
            "No ports configured. Check %s/%s",
            PTM_CONF_DIR, PTM_CONF_FILE);
        ptm_conf_ctl_cmd_error (event, errstr);
        return PTM_CMD_OK;
    }

    /* get debug cmd has only one option at this point */
    modstr = strtok_r(NULL, " ", &args);

    for (m = 0; modstr && m < MAX_MODULE; m++ ) {
        if (!strcasecmp(modstr, ptm_module_string(m)) &&
            PTM_MODULE_DEBUGCB(ptm_conf.ptmg, m)) {
            found = 1;
            break;
        }
    }

    if (modstr && !found) {
        return PTM_CMD_UNKNOWN;
    } else if (!modstr) {
        /* default get LLDP debug */
        m = LLDP_MODULE;
    }


    /* Initialize csv for using discrete record buffers */
    csv = csv_init(csv, NULL, CTL_MSG_SZ);
    ptm_hrec = ptm_msg_encode_header(csv, NULL, 0, PTM_VERSION);

    rval = PTM_MODULE_DEBUGCB(ptm_conf.ptmg, m)(csv, NULL, NULL,
                              NULL, NULL, errstr);

    DLOG("Got module %s rval %d \n", ptm_module_string(m), rval);

    if (rval != PTM_CMD_OK) {
        ptm_conf_ctl_cmd_error (event, errstr);
        rval = PTM_CMD_OK;
    } else {

        /* wrap up csv */
        ptm_msg_encode_header(csv, ptm_hrec, (csvlen(csv) - PTM_MSG_HEADER_LENGTH),
                PTM_VERSION);

        /* parse csv contents into string */
        csv_serialize(csv, msgbuf);

        DLOG("Sending %s\n", msgbuf);
        ptm_ctl_send(event->client, msgbuf, csvlen(csv));
        ptm_ctl_send(event->client, PTM_MSG_EOF_STR, PTM_MSG_EOF_LEN);
    }

    csv_clean(csv);
    csv_free(csv);
    return PTM_CMD_OK;
}

static ptm_cmd_rval
ptm_conf_ctl_cmd_get_status (ptm_event_t *event, char *args)
{
    struct ptm_conf_port *port, *tmp;
    csv_t *csv;
    char msgbuf[CTL_MSG_SZ];


    if (!ptm_conf.graph) {
        sprintf(msgbuf,
            "No valid topology file. Check %s/%s",
            PTM_CONF_DIR, PTM_CONF_FILE);
        ptm_conf_ctl_cmd_error (event, msgbuf);
        return PTM_CMD_OK;
    }

    if (!g_topo.me.ports) {
        sprintf(msgbuf,
            "No ports configured. Check %s/%s",
            PTM_CONF_DIR, PTM_CONF_FILE);
        ptm_conf_ctl_cmd_error (event, msgbuf);
        return PTM_CMD_OK;
    }

    HASH_ITER(ph, g_topo.me.ports, port, tmp) {
        csv = ptm_conf_get_port_status(port, event->client->inbuf, msgbuf);
        if (csv) {
            ptm_ctl_send(event->client, msgbuf, csvlen(csv));
            csv_clean(csv);
            csv_free(csv);
        }
    }

    ptm_ctl_send(event->client, PTM_MSG_EOF_STR, PTM_MSG_EOF_LEN);

    return PTM_CMD_OK;
}

static void
ptm_conf_free_node (void *data)
{
    if (data)
        free (data);
}

void
ptm_conf_process_client_query(ptm_event_t *event)
{
    int cmd_num;
    char *sargs = NULL;
    char *cmd;
    ptm_cmd_rval rval;
    char in_args[MAX_ARGLEN];

    assert(strlen(event->client->inbuf) <= MAX_ARGLEN);

    strcpy(in_args, event->client->inbuf);
    INFOLOG("%s args %s\n", __FUNCTION__, event->client->inbuf);

    if (strlen(event->client->inbuf) < 1)
        return;

    /* check for cmd */
    cmd = strtok_r(in_args, " ", &sargs);

    for (cmd_num = 0; cmd_num < PTM_CONF_MAX_CMDS; cmd_num++) {
        if ((ptm_conf_cmds[cmd_num].cmd_name) &&
            (strncmp(ptm_conf_cmds[cmd_num].cmd_name, cmd,
                    strlen(ptm_conf_cmds[cmd_num].cmd_name)) == 0)) {
            rval = ptm_conf_cmds[cmd_num].cmd_cb(event, sargs);
            if (rval != PTM_CMD_OK) {
                ERRLOG("%s: command %s error %s\n", __FUNCTION__,
                       event->client->inbuf, ptm_cmd_rval_string(rval));
                break;
            }
        }
    }

    if (rval == PTM_CMD_UNKNOWN) {
        ERRLOG("%s: Unknown command %s received from client fd %d\n",
           __FUNCTION__, event->client->inbuf, event->client->fd);
        ptm_conf_ctl_cmd_unknown(event, cmd);
    }
    return;
}

static int
ptm_conf_read (struct ptm_conf_network *topo)
{
    Agraph_t *g;
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
        ERRLOG ("agread failed (%s)\n", aglasterr());
        fclose(filestream);
        return (-1);
    }
    ptm_conf.graph = g;

    fclose(filestream);
    /* How do I know who I am ? IP Addr or name ? */
    id_type = ptm_conf_get_hostid_type (g);

    switch (id_type) {
    case PTM_HOST_ID_TYPE_NAME:
        ptm_conf_add_node (topo, id_type, ptm_conf.hostname, ptm_conf.hostip, TRUE);
        break;
    case PTM_HOST_ID_TYPE_IP:
        ptm_conf_add_node (topo, id_type, NULL, ptm_conf.hostip, TRUE);
        break;
    default:
        /* XX: Log error */
        ERRLOG ("idtype %d not supported\n", id_type);
        return (-1);
        break;
    }

    /* Fill in the topo data structure */
    status = ptm_conf_parse_graph(topo, g, &(topo->me), FALSE);

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
        if (host_addr != NULL) {
            strncpy(topo->me.mgmt_ip_addr, host_addr,
                    INET6_ADDRSTRLEN);
            topo->me.mgmt_ip_addr[INET6_ADDRSTRLEN] = '\0';
        }

        if (hostname != NULL) {
            topo->me.node_name[MAXNAMELEN] = '\0';
            strncpy(topo->me.node_name, hostname, MAXNAMELEN);
        } else if (host_addr) {
            strncpy(topo->me.node_name, host_addr, MAXNAMELEN);
        }

        topo->me.id_type = host_id_type;
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

    HASH_FIND(ph, node->ports, key, keylen, hport);
    if (!hport) {
        hport = (struct ptm_conf_port *)calloc(1, sizeof(struct ptm_conf_port));
        if (hport == NULL) {
            ERRLOG ("Malloc Fail! Unable to allocate ptm_conf_nbr structure for "
                    "port %s of node %s\n", key, node->node_name);
            return (NULL);
        }
        switch (cmp_type) {
        case PTM_NBR_CMP_PORT:
            hport->port_name[MAXNAMELEN] = '\0';
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
        HASH_ADD(ph, node->ports, port_name, keylen, hport);
    }

    return (hport);
}

static void
ptm_conf_parse_port_parms(struct ptm_conf_port *port, Agedge_t *edge)
{
    int mod;
    char *arg_str;

    for (mod=LLDP_MODULE; mod != MAX_MODULE; mod++) {
        arg_str = agget(edge, ptm_module_string(mod));
        if (!arg_str) {
            /* check for global setting */
            arg_str = agget(ptm_conf.graph, ptm_module_string(mod));
        }

        if (PTM_MODULE_GET_STATE(ptm_conf.ptmg, mod) == MOD_STATE_INITIALIZED) {
            if (PTM_MODULE_PARSECB(ptm_conf.ptmg, mod)) {
                PTM_MODULE_PARSECB(ptm_conf.ptmg, mod)(port, arg_str);
            }
        }
        if (arg_str || (mod == LLDP_MODULE)) {
            port->en_mods |= (1 << mod);
            DLOG("Enabled module %s on port %s\n", ptm_module_string(mod),
                 port->port_name);
        } else {
            DLOG("Disabled module %s on port %s\n", ptm_module_string(mod),
                 port->port_name);
        }
    }
}

static int
ptm_conf_parse_graph (struct ptm_conf_network *topo, Agraph_t *g,
				 struct ptm_conf_node *node, int reparse)
{
    Agnode_t *gnode = NULL;
    Agedge_t *edge;
    int id_type = PTM_HOST_ID_TYPE_NAME;
    ptm_module_e mod;

    /* XX: Handle IP addr based names later */
    assert(node->node_name[0] != '\0');
    id_type = ptm_conf_get_hostid_type (g);

    switch(id_type) {
    case PTM_HOST_ID_TYPE_NAME:
        gnode = agnode(g, node->node_name, FALSE);
        break;
    case PTM_HOST_ID_TYPE_IP:
        gnode = agnode(g, node->mgmt_ip_addr, FALSE);
        break;
    default:
        ERRLOG("idtype %d not supported\n", id_type);
    }

    if (gnode == NULL) {
        if ((ptm_conf.topo_retry_cnt < TOPO_RETRY_DISPLAY_INTERVAL) ||
            (ptm_conf.topo_retry_cnt % TOPO_RETRY_DISPLAY_INTERVAL)) {
            ERRLOG ("Unable to find node %s in graph\n", node->node_name);
        }
        ptm_conf.topo_retry_cnt++;
        return (-1);
    }

    for (edge = agfstin(g, gnode); edge; edge = agnxtin(g, edge)) {
        ptm_conf_process_graph_entry(topo, gnode, edge, PTM_CONF_EDGE_IN, node);
    }

    for (edge = agfstout(g, gnode); edge; edge = agnxtout(g, edge)) {
        ptm_conf_process_graph_entry(topo, gnode, edge, PTM_CONF_EDGE_OUT, node);
    }

    for (mod = 0; mod < MAX_MODULE; mod++) {
        if (PTM_MODULE_GET_STATE(ptm_conf.ptmg, mod) ==
                                        MOD_STATE_INITIALIZED) {
            PTM_MODULE_SET_STATE(ptm_conf.ptmg, mod, MOD_STATE_PARSE);
        }
    }

    ptm_conf.topo_retry_cnt = 0;

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

    DLOG("Found edge for %s:%s\n", ournode, ourport);

    if (strcmp(node->node_name, ournode) != 0) {
        DLOG ("graph node %s is not us(%s) - ignore\n",
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

    /* select per-edge compare criterion */
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

    /* pass port parms to all modules */
    ptm_conf_parse_port_parms(port, edge);

    DLOG("cmp type %d\n", type);

    port->cmp_attr = type;
    port->admin.sys_name[MAXNAMELEN] = '\0';
    strncpy(port->admin.sys_name, nbrnode, MAXNAMELEN);

    port->admin.port_ident[MAXNAMELEN] = '\0';
    strncpy(port->admin.port_ident, nbrport, MAXNAMELEN);

    time(&port->admin.last_change_time);
}

int
ptm_conf_is_mod_enabled(struct ptm_conf_port *port, ptm_module_e mod)
{
    if (port) {
        return !!(port->en_mods & (1 << mod));
    }
    return 0;
}

struct ptm_conf_port *
ptm_conf_get_port_by_name(char *port_name)
{
    struct ptm_conf_port *port = NULL;

    if (!port_name || !strlen(port_name)) {
        ERRLOG("%s: Invalid port name received\n", __func__);
        return 0;
    }

    if (g_topo.me.ports == NULL) {
        DLOG("%s: Ignoring port update as no config exists\n", __func__);
        return 0;
    }

    HASH_FIND(ph, g_topo.me.ports, port_name, strlen(port_name), port);

    if (port == NULL) {
        //DLOG("Port %s: Unable to find port\n", port_name);
        return 0;
    }
    return port;
}

struct ptm_conf_port *
ptm_conf_get_port(ptm_event_t *event)
{
    struct ptm_conf_port *port = NULL;

    if (!event || !event->liface || !strlen(event->liface)) {
        ERRLOG("%s: Invalid event received\n", __func__);
        return 0;
    }

    if (g_topo.me.ports == NULL) {
        DLOG("%s: Ignoring port update as no config exists\n", __func__);
        return 0;
    }

    HASH_FIND(ph, g_topo.me.ports, event->liface, strlen(event->liface), port);

    if (port == NULL) {
        //DLOG("Port %s: Unable to find port\n", event->liface);
        return 0;
    }
    return port;
}

void
ptm_conf_finish (void)
{
    struct ptm_conf_port *tmp, *port;

    if (g_topo.me.ports != NULL) {
        HASH_ITER(ph, g_topo.me.ports, port, tmp) {
            HASH_DELETE(ph, g_topo.me.ports, port);
            ptm_conf_free_node(port);
        }
        g_topo.me.ports = NULL;
    }

    if (g_topo.nodes != NULL) {
        assert (g_topo.nodes != NULL);
    }

    if (ptm_conf.graph) {
        agclose(ptm_conf.graph);
        ptm_conf.graph = NULL;
    }

    if (ptm_conf.ptmg) {
        ptm_conf.ptmg->conf_init_done = false;
    }
}

void
ptm_conf_get_template_str(char *tmpl_key, char *tmpl_str)
{
    char *t;

    tmpl_str[0] = '\0';
    if (tmpl_key && strlen(tmpl_key)) {
        t = agget(ptm_conf.graph, tmpl_key);
        if (t)
            strcpy(tmpl_str, t);
    }

    return;
}

void
ptm_conf_find_key_val(char *key_arg, char *args, char *val)
{
    char *vargs, *largs;
    char *sargs = NULL;
    char *key = NULL;
    char *in_val = NULL;
    char in_args[MAX_ARGLEN];

    strcpy(in_args, args);
    val[0] = '\0';

    largs = strtok_r(in_args, ", ", &sargs);
    while (largs != NULL) {
        /* skip over leading spaces */
        while(*largs == ' ')largs++;
        /* tokenize key */
        key = strtok_r(largs, "=", &vargs);
        if (key && !strcasecmp(key, key_arg)) {
            in_val = strtok_r(NULL, ",\n\0", &vargs);
            DLOG("%s: Found key [%s] val [%s]\n", __FUNCTION__, key, in_val);
            strcpy(val, in_val);
            break;
        }
        largs = strtok_r(NULL, ",\n\0", &sargs);
        vargs = NULL;
    }

    return;
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
            (strcmp(event->name, g_topo.graph_file) == 0)) {
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

    dirc = strdup(g_topo.graph_file);
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
