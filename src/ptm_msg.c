/* Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <unistd.h>

#include "csv.h"
#include "ptm_msg.h"
#include "log.h"

csv_record_t *
ptm_msg_encode_header (csv_t *csv,
		       csv_record_t *rec,
		       int msglen,
		       int version,
               char *cmd,
               char *client_name,
               int cmd_id)
{
  char msglen_buf[16], vers_buf[16], cmdid_buf[16];
  csv_record_t *rec1;

  sprintf(msglen_buf, "%4u", msglen);
  sprintf(vers_buf, "%4u", version);
  sprintf(cmdid_buf, "%4u", cmd_id);
  if (rec) {
    rec1 = csv_encode_record(csv, rec, 5, msglen_buf, vers_buf,
                      cmd, client_name, cmd_id_buf);
  } else {
    rec1 = csv_encode(csv, 5, msglen_buf, vers_buf,
                      cmd, client_name, cmd_id_buf);
  }
  return (rec1);
}

int
ptm_msg_decode_header (csv_t *csv,
                       int *msglen,
                       int *version,
                       char *cmd,
                       char *client_name,
                       int *cmd_id)
{
  char *hdr;
  csv_record_t *rec;
  csv_field_t *fld;

  csv_decode(csv);
  rec = csv_record_iter(csv);
  if (rec == NULL) {
    ERRLOG("malformed CSV\n");
    return (-1);
  }
  hdr = csv_field_iter(rec, &fld);
  if (hdr == NULL) {
    ERRLOG("malformed CSV\n");
    return (-1);
  }
  *msglen = atoi(hdr);
  hdr = csv_field_iter_next(&fld);
  if (hdr == NULL) {
    ERRLOG("malformed CSV\n");
    return (-1);
  }
  *version = atoi(hdr);
  hdr = csv_field_iter_next(&fld);
  if (hdr == NULL) {
    ERRLOG("malformed CSV\n");
    return (-1);
  }
  strcpy(cmd, hdr);
  hdr = csv_field_iter_next(&fld);
  if (hdr == NULL) {
    ERRLOG("malformed CSV\n");
    return (-1);
  }
  strcpy(client_name, hdr);
  hdr = csv_field_iter_next(&fld);
  if (hdr == NULL) {
    ERRLOG("malformed CSV\n");
    return (-1);
  }
  *cmd_id = atoi(hdr);
  return (0);
}
