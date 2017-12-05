/*********************************************************************
 * Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * ptm_test_client.[ch]: Test client interface for PTMD. Open unix
 * socket to PTMD and read/dump port status.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/un.h>

#include "ptm_msg.h"
#include "csv.h"

const char PTMD_CTL_SOCKET[] = "\0/var/run/ptmd.socket";

#define COLUMN_SIZE 25
static char sep[] = "-------------------------------------------------------------------------------\
";

static void
output_begin (char *hdr)
{
    fprintf(stderr, "\n%s\n%s\n%s\n", sep, hdr, sep);
}

static void
output_end ()
{
    fprintf(stderr, "\n");
}

static void
output_record()
{
    fprintf(stderr, "%s\n", sep);
}

static void
output_field (char *tag, char *data)
{
    int len;

    len = fprintf(stderr, "%s:", tag);
    fprintf(stderr, "%*s", (COLUMN_SIZE - len), " ");
    fprintf(stderr, "%s\n", data);
}

/**
 * Connect to the control Unix socket.
 *
 * @param name The name of the Unix socket.
 * @return The socket when successful, -1 otherwise.
 */
static int
ptmcli_ctl_connect ()
{
    int s;
    struct sockaddr_un su;
    int rc;

    if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "Create socket failed (%s)\n", strerror(errno));
        return (-1);
    }
    memset(su.sun_path, 0, sizeof(su.sun_path));
    su.sun_family = AF_UNIX;
    memcpy(su.sun_path, PTMD_CTL_SOCKET, sizeof(PTMD_CTL_SOCKET));
    if (connect(s, (struct sockaddr *)&su,
                sizeof(su.sun_family)+sizeof(PTMD_CTL_SOCKET)-1) == -1) {
        rc = errno;
	fprintf(stderr, "unable to connect to socket %s", PTMD_CTL_SOCKET);
	errno = rc; return -1;
    }
    return s;
}

static void
ptmcli_usage (char *argv0)
{
    fprintf(stderr, "usage: %s [OPTIONS ...]\n\n", argv0);
    fprintf(stderr, "-h    Print this usage.\n");
    fprintf(stderr, "-b    Get brief status about the interfaces\n");
    fprintf(stderr, "-v    Get detailed status about the interfaces\n");
    fprintf(stderr, "-w    Watch for PTM status of interfaces\n");
    fprintf(stderr, "See manual page for more information.\n");
    exit(10);
}

#define PTM_CLI_TAB_FMT "%6s %6s %20s %20s %10s\n"

#if 0
static void
ptmcli_dump_port_status_csv (csv_t *csv)
{
    #define MAX_FIELDS 12
    csv_record_t *fstrec, *rec;
    csv_field_t *fld;
    char *str;
    char *hdrfields[MAX_FIELDS];
    int i;

    /**
     * The first record contains the header fields. Store them separately.
     */
    fstrec = csv_record_iter(csv);
    for (str = csv_field_iter(fstrec, &fld), i = 0;
         i < MAX_FIELDS && str != NULL;
         i++, str = csv_field_iter_next(&fld)) {
        hdrfields[i] = str;
    }

    /* Go over the remaining records and their fields */
    for (rec = csv_record_iter_next(fstrec); rec;
         rec = csv_record_iter_next(rec)) {
        output_record();
        for (str = csv_field_iter(rec, &fld), i = 0;
             i < MAX_FIELDS && str != NULL;
             i++, str = csv_field_iter_next(&fld)) {
            output_field(hdrfields[i], str);
        }
        output_record();
    }
}
#else
static void
ptmcli_dump_port_status_csv (csv_t *csv)
{
    #define MAX_FIELDS 12
    csv_record_t *fstrec, *rec;
    csv_field_t *fld;
    char *str;
    //char *hdrfields[MAX_FIELDS];
    char *datafields[MAX_FIELDS];
    int i;

    /**
     * The first record contains the header fields. Store them separately.
     */
    fstrec = csv_record_iter(csv);
    for (str = csv_field_iter(fstrec, &fld), i = 0;
         i < MAX_FIELDS && str != NULL;
         i++, str = csv_field_iter_next(&fld)) {
        //hdrfields[i] = str;
    }

    /* Go over the remaining records and their fields */
    for (rec = csv_record_iter_next(fstrec); rec;
         rec = csv_record_iter_next(rec)) {

        for (str = csv_field_iter(rec, &fld), i = 0;
             i < MAX_FIELDS && str != NULL;
             i++, str = csv_field_iter_next(&fld)) {
            datafields[i] = str;
        }

        fprintf(stdout, PTM_CLI_TAB_FMT, datafields[0], datafields[1],
                datafields[2], datafields[3], datafields[4]);
    }
}
#endif

/*
 * Rreceive a given size of bytes from a stream socket. Works for blocking or
 * non-blocking sockets.
 */
static int
ptmcli_read_fixedlen_into_buffer (int fd,
                                  char *buf,
                                  int glen)
{
    int len = 0;
    int rc;

    while (len != glen) {
        rc = recv(fd, (buf+len), (glen-len), 0);
        if (rc < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                sleep(5);
            } else {
                fprintf(stderr, "recv error %s\n", strerror(errno));
                return (rc);
            }
        }
        len += rc;
    }
    return (len);
}

static int
ptmcli_read_brief_status (int fd,
                          int print)
{
    int len = 0;
    char rbuffer[BUFSIZ], *buf, *port, *status, *save;

    if (print) {
        output_begin("Port Status");
    }
    while (1) {
        len = 0;
        buf = rbuffer;
        len = ptmcli_read_fixedlen_into_buffer(fd, buf, PTM_MSG_EOF_LEN);
        if (len < 0) {
            return (len);
        }
        assert(len == PTM_MSG_EOF_LEN);
        rbuffer[len] = '\0';
        if (strcmp(rbuffer, PTM_MSG_EOF_STR) == 0) {
            //fprintf(stderr, "Done\n");
            return (0);
        }

        len = ptmcli_read_fixedlen_into_buffer(fd, (buf+len),
                            (PTM_MSG_GET_STATUS_LEN - PTM_MSG_EOF_LEN));
        if (len < 0) {
            return (len);
        }
        assert(len == (PTM_MSG_GET_STATUS_LEN - PTM_MSG_EOF_LEN));
        rbuffer[PTM_MSG_GET_STATUS_LEN] = '\0';
        if (print) {
            output_record();
            port = strtok_r(rbuffer, " ", &save);
            status = strtok_r(NULL, "\n", &save);
            output_field("Port", port);
            output_field("Status", status);
            output_record();
        }
    }
    if (print) {
        output_end();
    }
}

static int
ptmcli_read_detail_status (int fd)
{
    int len = 0;
    char rbuffer[BUFSIZ], *buf;
    csv_t *csv = NULL;
    int msglen = 0, ver;

    fprintf(stdout, PTM_CLI_TAB_FMT, "Port", "Status", "Expected-Nbr", "Observed-Nbr", "Last-Upd");
    output_record();

    while (1) {
        len = 0;
        buf = rbuffer;
        len = ptmcli_read_fixedlen_into_buffer(fd, buf, PTM_MSG_EOF_LEN);
        if (len < 0) {
            return (len);
        }
        assert(len == PTM_MSG_EOF_LEN);
        rbuffer[len] = '\0';
        if (strcmp(rbuffer, PTM_MSG_EOF_STR) == 0) {
            return (0);
        }

        len = ptmcli_read_fixedlen_into_buffer(fd, (buf+len),
                            (PTM_MSG_HEADER_LENGTH - PTM_MSG_EOF_LEN));
        if (len < 0) {
            return (len);
        }
        assert(len == (PTM_MSG_HEADER_LENGTH - PTM_MSG_EOF_LEN));
        rbuffer[PTM_MSG_HEADER_LENGTH] = '\0';
        csv = csv_init(csv, rbuffer, PTM_MSG_HEADER_LENGTH);
        ptm_msg_decode_header(csv, &msglen, &ver);
        csv_clean(csv);

        assert(msglen != 0);
        buf = rbuffer;
        len = ptmcli_read_fixedlen_into_buffer(fd, buf, msglen);
        if (len < 0) {
            return (len);
        }
        assert(len == msglen);
        rbuffer[len] = '\0';
        csv = csv_init(csv, rbuffer, msglen);
        csv_decode(csv);
        ptmcli_dump_port_status_csv(csv);
        csv_clean(csv);
    }
}

int
main (int argc, char *argv[])
{
    int fd;
    int len = 0;
    char rbuffer[BUFSIZ];
    int ch;
    int watch = 0;
    int brevity = 1;

    while ((ch = getopt(argc, argv, "bhvw")) != -1) {
        switch(ch) {
        case 'b':
            break;
        case 'v':
            brevity = 0;
            break;
        case 'w':
            watch = 1;
            break;
        case 'h':
        default:
            ptmcli_usage(argv[0]);
            break;
        }
    }

    fd = ptmcli_ctl_connect();
    if (fd < 0) {
        return (10);
    }

    /*
     * We always receive brief status dump from PTMD on connect. Read it off.
     * If not interested, dump it on the floor.
     */
    ptmcli_read_brief_status(fd, brevity);

    /*
     * Everything else is explicit. That is, if the request is for detailed
     * status, send an explicit message to PTMD to say so.
     */
    if (!brevity) {
        strcpy(rbuffer, "dump-status");
        len = send(fd, rbuffer, strlen(rbuffer)+1, 0);
        if (len < 0) {
            fprintf(stderr, "send error %s\n", strerror(errno));
            return (11);
        }
        //fprintf(stderr, "Sent %s\n", rbuffer);
        /* And receive the detailed status */
        ptmcli_read_detail_status(fd);
    }
    if (watch) {
        if (brevity) {
            ptmcli_read_brief_status(fd, brevity);
        } else {
            ptmcli_read_detail_status(fd);
        }
    }

    return (1);
}
