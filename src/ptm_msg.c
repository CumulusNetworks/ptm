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

#define PTM_MSG_HEADER_LENGTH 10
#define PTM_VERSION 1

csv_record_t *
ptm_msg_encode_header (csv_t *csv,
		       csv_record_t *rec,
		       int msglen,
		       int version)
{
  char hdr1[16], hdr2[16];
  csv_record_t *rec1;

  sprintf(hdr1, "%4u", msglen);
  sprintf(hdr2, "%4u", version);
  if (rec) {
    rec1 = csv_encode_record(csv, rec, 2, hdr1, hdr2);
  } else {
    rec1 = csv_encode(csv, 2, hdr1, hdr2);
  }
  return (rec1);
}

int
ptm_msg_decode_header (csv_t *csv,
		       int *msglen,
		       int *version)
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
  return (0);
}

