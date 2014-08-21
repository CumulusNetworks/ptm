/* Copyright 2013 Cumulus Networks, Inc.  All rights reserved. */

#ifndef __PTM_MSG_H__
#define __PTM_MSG_H__

#include "csv.h"
#include "ptm_conf.h"

#define PTM_MSG_GET_STATUS_LEN (IF_NAMESIZE + 6)
#define PTM_MSG_HEADER_LENGTH 10
#define PTM_VERSION 1
#define PTM_MSG_EOF_STR "EOF\n"
#define PTM_MSG_EOF_LEN 4
#define CSV_LEN(csv) ((csv)->csv_len)

csv_record_t *
ptm_msg_encode_header (csv_t *csv,
		       csv_record_t *rec,
		       int msglen,
		       int version);

int
ptm_msg_decode_header (csv_t *csv,
		       int *msglen,
		       int *version);

void
ptm_msg_encode_port_header (csv_t *csv);

void
ptm_msg_encode_port (csv_t *csv,
		     struct ptm_conf_port *port);

#endif
