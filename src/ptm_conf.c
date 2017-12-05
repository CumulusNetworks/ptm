/* Copyright 2013,2015 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php

 * Parse the ptm.conf file, perform topology validation and send
 * notification on topo pass, topo fail and interface down events.
 *
 */

#include "ptm_conf.h"
#include "log.h"
#include "ptm_ctl.h"
#include "ptm_lib.h"
#include "ptm_bfd.h"
#include "ptm_lldp.h"
#include "ptm_timer.h"
#include <sys/inotify.h>
#include <libgen.h>
#include <stdbool.h>
#include <strings.h>

typedef struct _ptm_conf_globals_t_ {
    char graph_file[MAXNAMELEN+1];
    char conf_dir[MAXNAMELEN+1];
    Agraph_t      *graph;
    ptm_globals_t *ptmg;
    char          *hostname;
    char          *mgmtip;
    struct ptm_conf_port *ports;
    char          err_str[CTL_MSG_SZ];
    char          id_type;
} ptm_conf_globals_t;

ptm_conf_globals_t ptm_conf;

typedef enum {
    PTM_CONF_EDGE_IN = 1,
    PTM_CONF_EDGE_OUT
} ptm_conf_edge_dir_t;

static char *HOST_ID_TYPE = "hostidtype";
static char *HOST_NAME_TYPE = "hostnametype";
static const char const *HOST_ID_TYPE_IP_STR = "ipaddr";
static const char const *HOST_ID_TYPE_NAME_STR = "hostname";
static const char const *HOST_NAME_TYPE_HOSTNAME_STR = "hostname";
static const char const *HOST_NAME_TYPE_FQDN_STR = "fqdn";

char const *PTM_PIDFILE = "/var/run/ptmd.pid";
/*
 * since this is now set in rsyslog.conf, this isn't really right, but
 * taking the logfile name out seems wrong also.
 */
char const *PTM_LOGFILE = "/var/log/ptmd.log"; /* may be incorrect... */
char const *PTM_CONF_DIR = "/etc/ptm.d";
char const *PTM_CONF_FILE = "topology.dot";
char const *PTM_TOPO_PASS_FILE = "if-topo-pass";
char const *PTM_TOPO_FAIL_FILE = "if-topo-fail";
char const *PTM_TMP_CONF_FILE = "tmptopo";

#define PTM_CONF_MAX_CMDS 16

struct ptm_conf_cmd_list {
    char *cmd_name;
    ptm_cmd_rval (* cmd_cb) (ptm_client_t *, void *);
};

static int ptm_conf_read(ptm_globals_t *ptmg);
static int ptm_conf_get_hostid_type(Agraph_t *g);
static void ptm_conf_parse_graph ();
static void ptm_conf_process_graph_entry (Agnode_t *gnode, Agedge_t *edge);
static void ptm_conf_update_nbr_from_graph (struct ptm_conf_port *port,
					    Agedge_t *edge, char *nbrnode, char *nbrport);
static void ptm_conf_get_status(void *, void *, char *, int *, int);
static ptm_cmd_rval ptm_conf_ctl_cmd_get_status (ptm_client_t *, void *);
static ptm_cmd_rval ptm_conf_ctl_cmd_start_bfd_sess (ptm_client_t *, void *);
static ptm_cmd_rval ptm_conf_ctl_cmd_stop_bfd_sess (ptm_client_t *, void *);
static ptm_cmd_rval ptm_conf_ctl_cmd_get_bfd_client (ptm_client_t *, void *);
static ptm_cmd_rval ptm_conf_ctl_cmd_reg_bfd_client (ptm_client_t *, void *);
static ptm_cmd_rval ptm_conf_ctl_cmd_dereg_bfd_client (ptm_client_t *, void *);

static struct ptm_conf_cmd_list ptm_conf_cmds[PTM_CONF_MAX_CMDS] = {
    {   .cmd_name = PTMLIB_CMD_GET_STATUS,
                    .cmd_cb = ptm_conf_ctl_cmd_get_status},
    {   .cmd_name = PTMLIB_CMD_START_BFD_SESS,
                    .cmd_cb = ptm_conf_ctl_cmd_start_bfd_sess},
    {   .cmd_name = PTMLIB_CMD_STOP_BFD_SESS,
                    .cmd_cb = ptm_conf_ctl_cmd_stop_bfd_sess},
    {   .cmd_name = PTMLIB_CMD_GET_BFD_CLIENT,
                    .cmd_cb = ptm_conf_ctl_cmd_get_bfd_client},
    {   .cmd_name = PTMLIB_CMD_REG_BFD_CLIENT,
                    .cmd_cb = ptm_conf_ctl_cmd_reg_bfd_client},
    {   .cmd_name = PTMLIB_CMD_DEREG_BFD_CLIENT,
                    .cmd_cb = ptm_conf_ctl_cmd_dereg_bfd_client},
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

    ptm_conf.ptmg = g;

    ptm_conf_finish();

    if (!g->my_hostname || !g->my_mgmtip) {
        /* hostname/mgmtip missing - delay again */
        sprintf (ptm_conf.err_str,
            "No Hostname/MgmtIP found [Check LLDPD daemon status]");
        DLOG("%s: Hostname (%s) and/or MgmtIP (%s) "
             "still missing post-pone config read\n",
             __FUNCTION__, g->my_hostname, g->my_mgmtip);
        return -1;
    }

    ptm_conf.graph_file[MAXNAMELEN] = '\0';
    strcpy(ptm_conf.graph_file, g->topo_file);
    strcpy(ptm_conf.conf_dir, PTM_CONF_DIR);
    if (ptm_conf.hostname)
        free(ptm_conf.hostname);
    if (ptm_conf.mgmtip)
        free(ptm_conf.mgmtip);
    ptm_conf.hostname = strdup(g->my_hostname);
    ptm_conf.mgmtip = strdup(g->my_mgmtip);

    status = ptm_conf_read(g);

    if (!status)
        g->conf_init_done = TRUE;

    return (status);
}

char *
ptm_conf_get_conf_dir(void)
{
    return ptm_conf.conf_dir;
}

void
ptm_conf_topo_action (void *p_ctxt, bool pass)
{
    char *cmd;
    char *msgbuf;

    if ((cmd = malloc(CMD_SZ)) == NULL)
        return;
    if ((msgbuf = malloc(CTL_MSG_SZ)) == NULL)
        return;
    ptm_conf_notify_status_all_clients(p_ctxt, msgbuf,
                            CTL_MSG_SZ, CONF_MODULE);
    sprintf(cmd, "%s/%s &", ptm_conf_get_conf_dir(),
            (pass)? PTM_TOPO_PASS_FILE:PTM_TOPO_FAIL_FILE);
    system(cmd);
    free(msgbuf);
    free(cmd);
}

void
ptm_conf_notify_status_all_clients(void *data, char *retbuf,
                                   int retlen, int module)
{
    ptm_client_t *client, *save;
    void *ctxt = NULL;

    /* create a get-status cmd */
    ptm_lib_init_msg(ptm_conf.ptmg->ptmlib_hdl, 0,
                     PTMLIB_MSG_TYPE_CMD, NULL, &ctxt);
    ptm_lib_append_msg(ptm_conf.ptmg->ptmlib_hdl, ctxt,
                       "cmd", PTMLIB_CMD_GET_STATUS);
    ptm_lib_append_msg(ptm_conf.ptmg->ptmlib_hdl, ctxt,
                       "module", ptm_module_string(module));

    /* get the response */
    ptm_conf_get_status(data, ctxt, retbuf, &retlen, TRUE);

    /* clean up the local cmd */
    ptm_lib_complete_msg(ptm_conf.ptmg->ptmlib_hdl, ctxt, NULL, NULL);

    for (client = ptm_client_safe_iter(&save); client;
         client = ptm_client_safe_iter_next(&save)) {

        /* dont send notifications to clients that have not sent a request
         * every client is expected to send a request before getting
         * notifications
         */
        if (!(PTM_CLIENT_GET_FLAGS(client) & PTM_CLIENT_REQUEST_RECD)) {
            continue;
        }

        ptm_ctl_send(client, retbuf, retlen);

        if (PTM_CLIENT_GET_FLAGS(client) & PTM_CLIENT_MARK_FOR_DELETION) {
            ptm_client_delete(client);
        }
    }
}

void
ptm_conf_get_status(void *m_ctxt,
                    void *in_ctxt,
                    char *msgbuf,
                    int  *msglen,
                    int  notify)
{
    int m, type;
    ptm_cmd_rval rval = PTM_CMD_OK;
    void *out_ctxt = NULL;

    if (notify)
        type = PTMLIB_MSG_TYPE_NOTIFICATION;
    else
        type = PTMLIB_MSG_TYPE_RESPONSE;

    ptm_lib_init_msg(ptm_conf.ptmg->ptmlib_hdl, 0, type, NULL, &out_ctxt);

    for (m = 0; m < MAX_MODULE; m++ ) {
        if (!PTM_MODULE_STATUSCB(ptm_conf.ptmg, m)) continue;

        rval = PTM_MODULE_STATUSCB(ptm_conf.ptmg, m)(m_ctxt, in_ctxt, out_ctxt);

        if (rval != PTM_CMD_OK) {
            ERRLOG("status_cb module %s rval %s\n",
                    ptm_module_string(m), ptm_cmd_rval_string(rval));
            break;
        }
    }

    ptm_lib_complete_msg(ptm_conf.ptmg->ptmlib_hdl, out_ctxt, msgbuf, msglen);

    return;
}

void
ptm_conf_ctl_cmd_status (ptm_client_t *client, void *in_ctxt,
                         char *arg, char *ext_arg)
{
    char *msgbuf;
    int buflen = CTL_MSG_SZ;
    void *out_ctxt;

    if ((msgbuf = malloc(buflen)) == NULL)
        return;

    ptm_lib_init_msg(ptm_conf.ptmg->ptmlib_hdl, 0,
                     PTMLIB_MSG_TYPE_RESPONSE, in_ctxt, &out_ctxt);
    ptm_lib_append_msg(ptm_conf.ptmg->ptmlib_hdl, out_ctxt,
                       "cmd_status", arg);
    ptm_lib_append_msg(ptm_conf.ptmg->ptmlib_hdl, out_ctxt,
                       "cmd_ext_status", ext_arg);
    ptm_lib_complete_msg(ptm_conf.ptmg->ptmlib_hdl, out_ctxt,
                         msgbuf, &buflen);

    DLOG("Sending %s\n", msgbuf);
    ptm_ctl_send(client, msgbuf, buflen);
    free(msgbuf);
}

static ptm_cmd_rval
ptm_conf_ctl_cmd_get_bfd_client (ptm_client_t *client, void *in_ctxt)
{
    ptm_cmd_rval rval;
    char msgbuf[CTL_MSG_SZ];
    char errstr[CTL_MSG_SZ];

    /* call into bfd handler */
    rval = ptm_bfd_get_client_handler(client, in_ctxt, msgbuf);

    if (rval != PTM_CMD_OK) {
        sprintf(errstr,
            "%s - please check %s for more info",
            msgbuf, PTM_LOGFILE);
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", errstr);
        return PTM_CMD_OK;
    }

    return PTM_CMD_OK;
}

static ptm_cmd_rval
ptm_conf_ctl_cmd_reg_bfd_client (ptm_client_t *client, void *in_ctxt)
{
    ptm_cmd_rval rval;
    char msgbuf[CTL_MSG_SZ];
    char errstr[CTL_MSG_SZ];

    /* call into bfd handler */
    rval = ptm_bfd_reg_client_handler(client, in_ctxt, msgbuf);

    if (rval != PTM_CMD_OK) {
        sprintf(errstr,
            "%s - please check %s for more info",
            msgbuf, PTM_LOGFILE);
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", errstr);
        return PTM_CMD_OK;
    }

    return PTM_CMD_OK;
}

static ptm_cmd_rval
ptm_conf_ctl_cmd_dereg_bfd_client (ptm_client_t *client, void *in_ctxt)
{
    ptm_cmd_rval rval;
    char msgbuf[CTL_MSG_SZ];
    char errstr[CTL_MSG_SZ];

    /* call into bfd handler */
    rval = ptm_bfd_dereg_client_handler(client, in_ctxt, msgbuf);

    if (rval != PTM_CMD_OK) {
        sprintf(errstr,
            "%s - please check %s for more info",
            msgbuf, PTM_LOGFILE);
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", errstr);
        return PTM_CMD_OK;
    }

    return PTM_CMD_OK;
}


static ptm_cmd_rval
ptm_conf_ctl_cmd_stop_bfd_sess (ptm_client_t *client, void *in_ctxt)
{
    ptm_cmd_rval rval;
    char errstr[CTL_MSG_SZ];
    char msgbuf[CTL_MSG_SZ];

    /* call into bfd handler */
    rval = ptm_bfd_stop_client_sess(client, in_ctxt, msgbuf);

    if (rval != PTM_CMD_OK) {
        sprintf(errstr,
            "%s - please check %s for more info",
            msgbuf, PTM_LOGFILE);
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", errstr);
        return PTM_CMD_OK;
    }

    return PTM_CMD_OK;
}

static ptm_cmd_rval
ptm_conf_ctl_cmd_start_bfd_sess (ptm_client_t *client, void *in_ctxt)
{
    ptm_cmd_rval rval;
    char msgbuf[CTL_MSG_SZ];
    char errstr[CTL_MSG_SZ];

    /* call into bfd handler */
    rval = ptm_bfd_start_client_sess(client, in_ctxt, msgbuf);

    if (rval != PTM_CMD_OK) {
        sprintf(errstr,
            "%s - please check %s for more info",
            msgbuf, PTM_LOGFILE);
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", errstr);
        return PTM_CMD_OK;
    }

    return PTM_CMD_OK;
}

static void
ptm_conf_get_lldp_status(ptm_client_t *client, void *in_ctxt)
{
    void *lldp = NULL;
    char msgbuf[CTL_MSG_SZ];
    int msglen;
    int found = FALSE;

    if (strlen(ptm_conf.err_str)) {
        sprintf(msgbuf,
            "%s - please check %s for more info",
            ptm_conf.err_str, PTM_LOGFILE);
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", msgbuf);
        return;
    }

    while((lldp = ptm_lldp_get_next_sess_iter(lldp)) != NULL) {
        found = TRUE;
        msglen = sizeof(msgbuf);
        ptm_conf_get_status(lldp, in_ctxt, msgbuf, &msglen, FALSE);
        ptm_ctl_send(client, msgbuf, msglen);
    }

    if (!found) {
        sprintf(msgbuf,
                "No LLDP ports detected. Check connections");
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", msgbuf);
        return;
    }
}

static void
ptm_conf_get_bfd_status(ptm_client_t *client, void *in_ctxt)
{
    bfd_status_ctxt_t b_ctxt;
    void *bfd = NULL;
    char msgbuf[CTL_MSG_SZ];
    int msglen;
    int found = FALSE;

    while((bfd = ptm_bfd_get_next_sess_iter(bfd)) != NULL) {
        found = TRUE;
        msglen = sizeof(msgbuf);
        memset(&b_ctxt, 0x00, sizeof(b_ctxt));
        b_ctxt.bfd = bfd;
        ptm_conf_get_status(&b_ctxt, in_ctxt, msgbuf, &msglen, FALSE);
        ptm_ctl_send(client, msgbuf, msglen);
    }

    if (!found) {
        sprintf(msgbuf,
                "No BFD sessions . Check connections");
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", msgbuf);
        return;
    }
}

static void
ptm_conf_get_port_status(ptm_client_t *client, void *in_ctxt)
{
    struct ptm_conf_port *port, *tmp;
    ptm_status_ctxt_t p_ctxt;
    char msgbuf[CTL_MSG_SZ];
    int msglen;

    if (strlen(ptm_conf.err_str)) {
        sprintf(msgbuf,
            "%s - please check %s for more info",
            ptm_conf.err_str, PTM_LOGFILE);
        ptm_conf_ctl_cmd_status (client, in_ctxt, "fail", msgbuf);
        return;
    }

    HASH_ITER(ph, ptm_conf.ports, port, tmp) {
        p_ctxt.port = port;
        p_ctxt.bfd_get_next = TRUE;
        p_ctxt.bfd_peer[0] = '\0';

        /* there can be multiple bfd sessions per interface due to
         * afi=BFD_AFI_BOTH param.
         */
        do {
            char prev[MAXNAMELEN];
            msglen = sizeof(msgbuf);
            strcpy(prev, p_ctxt.bfd_peer);
            ptm_conf_get_status(&p_ctxt, in_ctxt, msgbuf, &msglen, FALSE);
            if (!strlen(prev) || strlen(p_ctxt.bfd_peer))
                ptm_ctl_send(client, msgbuf, msglen);
        } while (strlen(p_ctxt.bfd_peer));
    }
}

static ptm_cmd_rval
ptm_conf_ctl_cmd_get_status (ptm_client_t *client, void *in_ctxt)
{
    char val[MAXNAMELEN];

    if (ptm_lib_find_key_in_msg(in_ctxt, "module", val) < 0)
        strcpy(val, ptm_module_string(CONF_MODULE));

    if (!strcasecmp(val, ptm_module_string(BFD_MODULE))) {
        /* user asking for BFD status only */
        ptm_conf_get_bfd_status(client, in_ctxt);
    } else if (!strcasecmp(val, ptm_module_string(LLDP_MODULE))) {
        /* user asking for LLDP status only */
        ptm_conf_get_lldp_status(client, in_ctxt);
    } else {
        /* default to topology file based status */
        ptm_conf_get_port_status(client, in_ctxt);
    }

    return PTM_CMD_OK;
}

static void
ptm_conf_free_node (void *data)
{
    if (data)
        free (data);
}

int
ptm_conf_process_client_cmd(void *arg, void *in_ctxt)
{
    ptm_client_t *client = arg;
    int cmd_num;
    char cmd[MAXNAMELEN];
    ptm_cmd_rval rval;

    ptm_lib_find_key_in_msg(in_ctxt, "cmd", cmd);
    for (cmd_num = 0; cmd_num < PTM_CONF_MAX_CMDS; cmd_num++) {
        if ((ptm_conf_cmds[cmd_num].cmd_name) &&
            (strncmp(ptm_conf_cmds[cmd_num].cmd_name, cmd,
                    strlen(ptm_conf_cmds[cmd_num].cmd_name)) == 0)) {
            PTM_CLIENT_SET_FLAGS(client, PTM_CLIENT_REQUEST_RECD);
            rval = ptm_conf_cmds[cmd_num].cmd_cb(client, in_ctxt);
            if (rval != PTM_CMD_OK) {
                ERRLOG("%s: command %s error %s\n", __FUNCTION__,
                       cmd, ptm_cmd_rval_string(rval));
                break;
            }
        }
    }

    if (rval == PTM_CMD_UNKNOWN) {
        ERRLOG("%s: Unknown command %s received from client fd %d\n",
           __FUNCTION__, cmd, client->fd);
        ptm_conf_ctl_cmd_status (client, in_ctxt,
                                 "fail", "Command Unsupported");
    }

    return 0;
}

/* Goal of this routine is to parse
 * the topo file and eliminate
 * DOT file semantics that might cause
 * unintended behavior when we call agread and
 * subsequent attribute parsing
 */
static FILE *
ptm_conf_pre_parse_topo_file(FILE *fs)
{
    char buf[1024];
    char file[MAXNAMELEN];
    char *s, *rpl;
    FILE *newfs;
    int lineno = 0;

    DLOG ("Pre-parse topology file\n");

    /* open a temp filestream for saving modifications */
    sprintf(file, "%s/%s", PTM_CONF_DIR, PTM_TMP_CONF_FILE);
    newfs = fopen(file, "w");
    if (!newfs) {
        INFOLOG ("Could not open tmp file for preparse [%m]\n");
        return fs;
    }
    while(fgets(buf, 1024, fs) != NULL) {
        lineno++;
        /*
         * replace empty string module keyword BFD=""
         * with BFD="default"
         */
        if ((s = strstr(buf, ptm_module_string(BFD_MODULE))) != NULL) {
            s += strlen(ptm_module_string(BFD_MODULE));
            /* skip over spaces */
            while (*s == ' ')s++;
            if (*s == '=') {
                s++;
                /* skip over spaces */
                while (*s == ' ')s++;
                if ((*s == '"') && (*(s+1) == '"')) {
                    /* empty string supplied
                     * replace "" with "default"
                     */
                    char *dflt = "default";
                    char tmpbuf[1024];
                    DLOG("Empty BFD param detected - replace (line %d)\n",
                         lineno);
                    rpl = s+1;
                    strcpy(tmpbuf, rpl);
                    strcpy(rpl, dflt);
                    rpl+=strlen(dflt);
                    strcpy(rpl, tmpbuf);
                }
            }
        }
        /*
         * replace "tailport"/"headport" param with "taxxport"/"hexxport"
         */
        if ((s = strstr(buf, HEADPORT_ID)) != NULL) {
            s[2] = s[3] = 'x';
            DLOG("%s detected - replace (line %d)\n", HEADPORT_ID, lineno);
        }
        if ((s = strstr(buf, TAILPORT_ID)) != NULL) {
            s[2] = s[3] = 'x';
            DLOG("%s detected - replace (line %d)\n", TAILPORT_ID, lineno);
        }
        fputs(buf, newfs);
    }

    /* cannot get agread to work properly without close/re-open of file */
    fflush(newfs);
    fclose(newfs);
    newfs = fopen(file, "r");
    if (!newfs) {
        INFOLOG ("Could not re-open tmp file for preparse [%m]\n");
        return fs;
    }
    /* close the old filestream */
    fclose(fs);
    return newfs;
}

static int
ptm_conf_read(ptm_globals_t *ptmg)
{
    Agraph_t *g;
    FILE *filestream = NULL;
    int fd;
    char *str;

    DLOG ("Reading topology file %s\n", ptm_conf.graph_file);

    fd = open(ptm_conf.graph_file, 0, S_IRUSR);
    if (fd) {
        fsync(fd);
        filestream = fdopen(fd, "r");
    }
    if (filestream == NULL) {
        sprintf (ptm_conf.err_str,
                "Topology file error [%s] [cannot open file]",
                ptm_conf.graph_file);
        ERRLOG ("%s - check file existence and permissions\n",
                ptm_conf.err_str);
        return (-1);
    }

    /* parse the topo file and prep it for agread */
    filestream = ptm_conf_pre_parse_topo_file(filestream);

    g = agread(filestream, NIL(Agdisc_t *));

    if (g == NULL) {
        str = aglasterr();
        if (!str || !strlen(str))
            str = "parse failure";
        sprintf (ptm_conf.err_str,
                "Topology file error [%s] [%s]",
                ptm_conf.graph_file, str);
        ERRLOG ("%s - Need to restart PTMD after fixing syntax error\n",
                ptm_conf.err_str);
        fclose(filestream);
        return (-1);
    }
    ptm_conf.graph = g;
    fclose(filestream);

    if (ptm_conf_get_hostname_type () == PTM_HOST_NAME_TYPE_HOSTNAME) {
        ptmg->my_hostname = ptm_conf_prune_hostname(ptmg->my_hostname);
        free(ptm_conf.hostname);
        ptm_conf.hostname = strdup(ptmg->my_hostname);
    }

    ptm_conf.id_type = ptm_conf_get_hostid_type (g);

    /* Fill in the topo data structure */
    ptm_conf_parse_graph();

    return 0;
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

int
ptm_conf_get_hostname_type (void)
{
    char *attr;
    int name_type = PTM_HOST_NAME_TYPE_HOSTNAME;
    Agraph_t *g = ptm_conf.graph;

    attr = agget(g, HOST_NAME_TYPE);
    if (attr != NULL) {
        if (strcmp (attr, HOST_NAME_TYPE_HOSTNAME_STR) == 0)
            name_type = PTM_HOST_NAME_TYPE_HOSTNAME;
        else if (strcmp (attr, HOST_NAME_TYPE_FQDN_STR) == 0)
            name_type = PTM_HOST_NAME_TYPE_FQDN;
        else
            name_type = PTM_HOST_NAME_TYPE_UNKNOWN;
    }

    return (name_type);
}

static struct ptm_conf_port *
ptm_conf_add_port (char *portname)
{
    struct ptm_conf_port *hport = NULL;

    HASH_FIND(ph, ptm_conf.ports, portname, strlen(portname), hport);
    if (!hport) {
        hport = (struct ptm_conf_port *)
                    calloc(1, sizeof(struct ptm_conf_port));
        if (hport == NULL) {
            ERRLOG ("Malloc Fail! port %s of node %s\n",
                    portname, ptm_conf.hostname);
            return (NULL);
        }
        hport->port_name[MAXNAMELEN] = '\0';
        strncpy (hport->port_name, portname, MAXNAMELEN);
        HASH_ADD(ph, ptm_conf.ports, port_name, strlen(portname), hport);
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
        if (!arg_str || !strlen(arg_str)) {
            /* check for global setting */
            arg_str = agget(ptm_conf.graph, ptm_module_string(mod));
        }

        if (PTM_MODULE_PARSECB(ptm_conf.ptmg, mod))
            PTM_MODULE_PARSECB(ptm_conf.ptmg, mod)(port, arg_str);

        if ((arg_str && strlen(arg_str)) || (mod == LLDP_MODULE)) {
            port->en_mods |= (1 << mod);
            DLOG("Enabled module %s on port %s\n", ptm_module_string(mod),
                 port->port_name);
        } else {
            DLOG("Disabled module %s on port %s\n", ptm_module_string(mod),
                 port->port_name);
        }
    }
}

static void
ptm_conf_parse_graph ()
{
    Agraph_t *g = ptm_conf.graph;
    Agnode_t *gnode;
    Agedge_t *edge;
    char *node_ident;

    switch(ptm_conf.id_type) {
    case PTM_HOST_ID_TYPE_IP:
        node_ident = ptm_conf.mgmtip;
        break;
    case PTM_HOST_ID_TYPE_NAME:
    default:
        node_ident = ptm_conf.hostname;
        break;
    }

    gnode = agnode(g, node_ident, FALSE);

    if (gnode == NULL) {
        sprintf (ptm_conf.err_str,
                 "Topology file error [%s] [cannot find node %s]",
                 ptm_conf.graph_file, node_ident);
        return;
    }

    for (edge = agfstedge(g, gnode);
         edge;
         edge = agnxtedge(g, edge, gnode)){
        ptm_conf_process_graph_entry(gnode, edge);
    }

    return;
}

static void
ptm_conf_process_graph_entry (Agnode_t *gnode,
                              Agedge_t *edge)
{
    char *headname, *tailname;
    char *ournode, *ourport;
    char *nbrnode, *nbrport;
    struct ptm_conf_port *hport;

    headname = agnameof(aghead(edge));
    tailname = agnameof(agtail(edge));

    if (strcmp(headname, ptm_conf.hostname) == 0) {
        ournode = headname;
        ourport = agget(edge, HEADPORT_ID);
        nbrnode = tailname;
        nbrport = agget(edge, TAILPORT_ID);
    } else {
        ournode = tailname;
        ourport = agget(edge, TAILPORT_ID);
        nbrnode = headname;
        nbrport = agget(edge, HEADPORT_ID);
    }

    DLOG("Found edge for %s:%s -- %s:%s\n", ournode, ourport,
         nbrnode, nbrport);

    hport = ptm_conf_add_port(ourport);
    if (hport == NULL)
        return;

    ptm_conf_update_nbr_from_graph(hport, edge, nbrnode, nbrport);
}

static void
ptm_conf_update_nbr_from_graph (struct ptm_conf_port *port, Agedge_t *edge,
                                char *nbrnode, char *nbrport)
{
    /* pass port parms to all modules */
    ptm_conf_parse_port_parms(port, edge);

    port->nbr_sysname[MAXNAMELEN] = '\0';
    if (nbrnode)
        strncpy(port->nbr_sysname, nbrnode, MAXNAMELEN);

    port->nbr_ident[MAXNAMELEN] = '\0';
    if (nbrport)
        strncpy(port->nbr_ident, nbrport, MAXNAMELEN);
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
        ERRLOG("%s: NULL port name received\n", __func__);
        return NULL;
    }

    if (ptm_conf.ports == NULL) {
        DLOG("%s: Ignoring port %s update as no config exists\n", __func__, port_name);
        return NULL;
    }

    HASH_FIND(ph, ptm_conf.ports, port_name, strlen(port_name), port);

    return port;
}

struct ptm_conf_port *
ptm_conf_get_port(ptm_event_t *event)
{
    struct ptm_conf_port *port = NULL;

    if (!event || !event->liface || !strlen(event->liface)) {
        DLOG("%s: Invalid event received\n", __func__);
        return NULL;
    }

    if (ptm_conf.ports == NULL) {
        // DLOG("%s: Ignoring port update as no config exists\n", __func__);
        return NULL;
    }

    HASH_FIND(ph, ptm_conf.ports, event->liface, strlen(event->liface), port);

    return port;
}

void
ptm_conf_finish (void)
{
    struct ptm_conf_port *tmp, *port;

    if (ptm_conf.ports != NULL) {
        HASH_ITER(ph, ptm_conf.ports, port, tmp) {
            HASH_DELETE(ph, ptm_conf.ports, port);
            ptm_conf_free_node(port);
        }
        ptm_conf.ports = NULL;
    }

    if (ptm_conf.graph) {
        agclose(ptm_conf.graph);
        ptm_conf.graph = NULL;
    }

    ptm_conf.ptmg->conf_init_done = FALSE;
    memset(ptm_conf.err_str, 0x00, sizeof(ptm_conf.err_str));
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

int
ptm_conf_parse_msec_parm(char *val)
{
    int value;

    value = ptm_conf_parse_ulong_parm(val);

    if (((value * MSEC_PER_SEC) >= LONG_MAX) ||
        ((value * MSEC_PER_SEC) <= LONG_MIN)) {
        ERRLOG("%s: out of range - skipping %ld\n", __FUNCTION__,
               (value * MSEC_PER_SEC));
        return -1;
    }
    return (value * MSEC_PER_SEC);
}

int
ptm_conf_parse_ulong_parm(char *val)
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
            if (in_val)
                strcpy(val, in_val);
            else
                val[0] = '\0';
            break;
        }
        largs = strtok_r(NULL, ",\n\0", &sargs);
        vargs = NULL;
    }

    return;
}

char *
ptm_conf_prune_hostname(char *host_name)
{
    char *tmpstr = strdup(host_name);
    char *saveptr, *tok;
    /* check if fqdn supplied and if yes - prune it */
    tok = strtok_r(tmpstr, ".", &saveptr);
    if (!tok) {
        /* assume only hostname supplied */
        tok = tmpstr;
    }
    free(host_name);
    return tok;
}
