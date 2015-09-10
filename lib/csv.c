#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <unistd.h>
#include "csv.h"

#define DEBUG_E 1
#define DEBUG_V 1

#define log_error(fmt, ...) \
  do { if (DEBUG_E) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			    __LINE__, __func__, ##__VA_ARGS__); } while (0)

#define log_verbose(fmt, ...) \
  do { if (DEBUG_V) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			    __LINE__, __func__, __VA_ARGS__); } while (0)

struct _csv_field_t_ {
  TAILQ_ENTRY(_csv_field_t_) next_field;
  char *field;
  int field_len;
};

struct _csv_record_t_ {
  TAILQ_HEAD(, _csv_field_t_) fields;
  TAILQ_ENTRY(_csv_record_t_) next_record;
  char *record;
  int rec_len;
};

struct _csv_t_ {
  TAILQ_HEAD(, _csv_record_t_) records;
  char *buf;
  int buflen;
  int csv_len;
  int pointer;
  int num_recs;
};


int
csvlen (csv_t *csv)
{
  return (csv->csv_len);
}

csv_t *
csv_init (csv_t *csv,
	  char *buf,
	  int buflen)
{
  if (csv == NULL) {
    csv = malloc(sizeof(csv_t));
    if (csv == NULL) {
      log_error("CSV Malloc failed\n");
      return (NULL);
    }
  }
  memset(csv, 0, sizeof(csv_t));

  csv->buf = buf;
  csv->buflen = buflen;
  TAILQ_INIT(&(csv->records));
  return (csv);
}

void
csv_clean (csv_t *csv)
{
  csv_record_t *rec;
  csv_record_t *rec_n;

  rec = TAILQ_FIRST(&(csv->records));
  while (rec != NULL) {
    rec_n = TAILQ_NEXT(rec, next_record);
    csv_remove_record(csv, rec);
    rec = rec_n;
  }
}

void
csv_free (csv_t *csv)
{
  if (csv != NULL) {
    free(csv);
  }
}

static void
csv_init_record (csv_record_t *record)
{
  TAILQ_INIT(&(record->fields));
}

csv_record_t *
csv_record_iter (csv_t *csv)
{
  return(TAILQ_FIRST(&(csv->records)));
}

csv_record_t *
csv_record_iter_next (csv_record_t *rec)
{
  return(TAILQ_NEXT(rec, next_record));
}

char *
csv_field_iter (csv_record_t *rec,
		csv_field_t **fld)
{
  *fld = TAILQ_FIRST(&(rec->fields));
  return ((*fld)->field);
}

char *
csv_field_iter_next (csv_field_t **fld)
{
  *fld = TAILQ_NEXT(*fld, next_field);
  if ((*fld) == NULL) {
    return (NULL);
  }
  return ((*fld)->field);
}

csv_record_t *
csv_encode (csv_t *csv,
	    int count,
	    ...)
{
  int tempc;
  va_list list;
  char *buf = csv->buf;
  int len = csv->buflen;
  int pointer = csv->pointer;
  char *str = NULL;
  int tlen = 0;
  char *col;
  csv_record_t *rec;
  csv_field_t *fld;

  if (buf) {
     str = buf + pointer;
  } else {
     /* allocate sufficient buffer */
     str = (char *)malloc(csv->buflen);
     if (!str) {
        log_error("field str malloc failed\n");
        return (NULL);
     }
  }

  va_start(list, count);
  rec = malloc(sizeof(csv_record_t));
  if (!rec) {
    log_error("record malloc failed\n");
    return (NULL);
  }
  csv_init_record(rec);
  rec->record = str;
  TAILQ_INSERT_TAIL(&(csv->records), rec, next_record);
  csv->num_recs++;

  /**
   * Iterate through the fields passed as a variable list and add them
   */
  for (tempc = 0; tempc < count; tempc++) {
    fld = malloc(sizeof(csv_field_t));
    if (!fld) {
      log_error("field malloc failed\n");
      /* more cleanup needed */
      return (NULL);
    }
    fld->field = (str+tlen);
    TAILQ_INSERT_TAIL(&(rec->fields), fld, next_field);
    col = va_arg(list, char *);
    if (col) {
      fld->field_len = snprintf((str+tlen), (len - tlen), "%s", col);
      tlen += fld->field_len;
    }
    if (tempc < (count - 1)) {
      tlen += snprintf((str+tlen), (len - tlen), ",");
    }
  }
  tlen += snprintf((str+tlen), (len - tlen), "\n");
  va_end(list);
  rec->rec_len = tlen;
  csv->csv_len += tlen;
  csv->pointer = csv->pointer + tlen;
  return (rec);
}

csv_record_t *
csv_encode_record (csv_t *csv,
		   csv_record_t *rec,
		   int count,
		   ...)
{
  int tempc;
  va_list list;
  char *str;
  char *col;
  csv_field_t *fld;
  int i;

  va_start(list, count);
  str = csv_field_iter(rec, &fld);
  for (tempc = 0; tempc < count; tempc++) {
    col = va_arg(list, char *);
    for (i = 0; i < fld->field_len; i++) {
      str[i] = col[i];
    }
    str = csv_field_iter_next(&fld);
  }
  va_end(list);
  return (rec);
}

void
csv_serialize(csv_t *csv, char *msgbuf)
{
  csv_record_t *rec;
  int offset = 0;

  if (!csv || !msgbuf) return;

  rec = csv_record_iter(csv);
  while (rec != NULL) {
    offset += sprintf(&msgbuf[offset], "%s", rec->record);
    rec = csv_record_iter_next(rec);
  }
}

void
csv_remove_record (csv_t *csv, csv_record_t *rec)
{
  csv_field_t *fld, *p_fld;

  /* first check if rec belongs to this csv */
  if(!csv_is_record_valid(csv, rec)){
    log_error("rec not in this csv\n");
    return;
  }

  /* remove fields */
  csv_field_iter(rec, &fld);
  while(fld) {
    p_fld = fld; 
    csv_field_iter_next(&fld);
    TAILQ_REMOVE(&(rec->fields), p_fld, next_field);
    free(p_fld);
  }
  
  TAILQ_REMOVE(&(csv->records), rec, next_record);
  csv->num_recs--;
  csv->csv_len -= rec->rec_len;
  if (!csv->buf)
    free(rec->record);
  free(rec);
}

void
csv_insert_record (csv_t *csv, csv_record_t *rec)
{
  /* first check if rec already in csv */
  if(csv_is_record_valid(csv, rec)){
    log_error("rec already in this csv\n");
    return;
  }

  /* we can only insert records if no buf was supplied during csv init */
  if (csv->buf) {
    log_error("un-supported for this csv type - single buf detected\n");
    return;
  }

  /* do we go beyond the max buf set for this csv ?*/
  if ((csv->csv_len + rec->rec_len) > csv->buflen ) {
    log_error("cannot insert - exceeded buf size\n");
    return;
  }

  TAILQ_INSERT_TAIL(&(csv->records), rec, next_record);
  csv->num_recs++;
  csv->csv_len += rec->rec_len;
}

csv_record_t *
csv_concat_record (csv_t *csv,
		           csv_record_t *rec1,
		           csv_record_t *rec2)
{
  char *curr;
  char *ret, *field;
  csv_field_t *fld;
  csv_record_t *rec;

  /* first check if rec1 and rec2 belong to this csv */
  if(!csv_is_record_valid(csv, rec1) ||
     !csv_is_record_valid(csv, rec2)) {
    log_error("rec1 and/or rec2 invalid\n");
    return (NULL);
  }

  /* we can only concat records if no buf was supplied during csv init */
  if (csv->buf) {
    log_error("un-supported for this csv type - single buf detected\n");
    return (NULL);
  }

  /* create a new rec */
  rec = malloc(sizeof(csv_record_t));
  if (!rec) {
    log_error("record malloc failed\n");
    return (NULL);
  }
  csv_init_record(rec);

  curr = (char *)calloc(1, csv->buflen);
  if (!curr) {
    log_error("field str malloc failed\n");
    return (NULL);
  }
  rec->record = curr;

  /* concat the record string */
  ret = strstr(rec1->record, "\n");
  if (!ret) {
    log_error("rec1 str not properly formatted\n");
    return (NULL);
  }

  snprintf(curr, (int)(ret - rec1->record + 1), "%s", rec1->record);
  strcat(curr, ",");

  ret = strstr(rec2->record, "\n");
  if (!ret) {
    log_error("rec2 str not properly formatted\n");
    return (NULL);
  }

  snprintf((curr+strlen(curr)), (int)(ret - rec2->record + 1), "%s", rec2->record);
  strcat(curr, "\n");
  rec->rec_len = strlen(curr);

  /* paranoia */
  assert(csv->buflen >
         (csv->csv_len - rec1->rec_len - rec2->rec_len + rec->rec_len));

  /* encode fields in new record */
  field = strpbrk(curr, ",");
  while (field != NULL) {
      ret = curr;
      fld = malloc(sizeof(csv_field_t));
      if (fld) {
        TAILQ_INSERT_TAIL(&(rec->fields), fld, next_field);
        fld->field = ret;
        fld->field_len = ret-curr;
      }
      curr = field + 1;
      field = strpbrk(curr, ",");
  }
  field = strstr(curr, "\n");
  fld = malloc(sizeof(csv_field_t));
  if (field && fld) {
    fld->field = curr;
    fld->field_len = field - curr;
    TAILQ_INSERT_TAIL(&(rec->fields), fld, next_field);
  }

  /* now remove rec1 and rec2 and insert rec into this csv */
  csv_remove_record(csv, rec1);
  csv_remove_record(csv, rec2);
  csv_insert_record(csv, rec);

  return rec;
}

void
csv_decode (csv_t *csv)
{
  char *buf = csv->buf;
  char *save1;
  char *running = strdup(buf);
  char *record;
  char *field;
  char *curr;
  char *ret;
  csv_record_t *rec;
  csv_field_t *fld;

  record = strtok_r(running, "\n", &save1);
  while (record != NULL) {
    rec = malloc(sizeof(csv_record_t));
    csv_init_record(rec);
    TAILQ_INSERT_TAIL(&(csv->records), rec, next_record);
    csv->num_recs++;
    rec->record = record;
    curr = record;
    field = strpbrk(curr, ",");
    while (field != NULL) {
      ret = curr;
      curr = field + 1;
      *field = '\0';
      fld = malloc(sizeof(csv_field_t));
      TAILQ_INSERT_TAIL(&(rec->fields), fld, next_field);
      fld->field = ret;
      fld->field_len = strlen(ret);
      field = strpbrk(curr, ",");
    }
    fld = malloc(sizeof(csv_field_t));
    fld->field = curr;
    TAILQ_INSERT_TAIL(&(rec->fields), fld, next_field);
    record = strtok_r(NULL, "\n", &save1);
  }
}

int
csv_is_record_valid(csv_t *csv, csv_record_t *in_rec)
{
  csv_record_t *rec;
  int valid = 0;

  rec = csv_record_iter(csv);
  while (rec) {
    if(rec == in_rec) {
      valid = 1;
      break;
    }
    rec = csv_record_iter_next(rec);
  }

  return valid;
}

void
csv_dump (csv_t *csv)
{
  csv_record_t *rec;
  csv_field_t *fld;
  char *str;

  rec = csv_record_iter(csv);
  while (rec != NULL) {
    str = csv_field_iter(rec, &fld);
    while (str != NULL) {
      fprintf(stderr, "%s\n", str);
      str = csv_field_iter_next(&fld);
    }
    rec = csv_record_iter_next(rec);
  }
}

#ifdef TEST_CSV

static int
get_memory_usage (pid_t pid)
{
  int fd, data, stack;
  char buf[4096], status_child[BUFSIZ];
  char *vm;

  sprintf(status_child, "/proc/%d/status", pid);
  if ((fd = open(status_child, O_RDONLY)) < 0)
    return -1;

  read(fd, buf, 4095);
  buf[4095] = '\0';
  close(fd);

  data = stack = 0;

  vm = strstr(buf, "VmData:");
  if (vm) {
    sscanf(vm, "%*s %d", &data);
  }
  vm = strstr(buf, "VmStk:");
  if (vm) {
    sscanf(vm, "%*s %d", &stack);
  }

  return data + stack;
}

int main ()
{
  char buf[10000];
  csv_t csv;
  int p;
  int i, j;
  csv_record_t *rec;
  csv_field_t *fld;
  char *str;
  char hdr1[32], hdr2[32];

  log_verbose("Mem: %ld\n", get_memory_usage(getpid()));
  csv_init(&csv, buf, 256);
  sprintf(hdr1, "%4u", 0);
  sprintf(hdr2, "%4u", 1);
  log_verbose("(%d/%d/%d/%d)\n", strlen(hdr1),
	  strlen(hdr2), atoi(hdr1), atoi(hdr2));
  rec = csv_encode(&csv, 2, hdr1, hdr2);
  csv_encode(&csv, 4, "name", "age", "sex", "hei");
  csv_encode(&csv, 3, NULL, "0", NULL);
  csv_encode(&csv, 2, "p", "35");
  for (i=0; i < 50; i++) {
    csv_encode(&csv, 2, "p", "10");
  }
  csv_encode(&csv, 2, "pdfadfadfadsadsaddfdfdsfdsd",
  		 "35444554545454545");
  log_verbose("%s\n", buf);
  sprintf(hdr1, "%4u", csv.csv_len);
  sprintf(hdr2, "%4u", 1);
  log_verbose("(%d/%d/%d/%d)\n", strlen(hdr1),
	  strlen(hdr2), atoi(hdr1), atoi(hdr2));
  rec = csv_encode_record(&csv, rec, 2, hdr1, hdr2);
  log_verbose("(%d/%d)\n%s\n", rec->rec_len, csv.csv_len, buf);

  log_verbose("Mem: %ld\n", get_memory_usage(getpid()));
  csv_clean(&csv);
  log_verbose("Mem: %ld\n", get_memory_usage(getpid()));
  csv_init(&csv, buf, 256);
  csv_decode(&csv);
  log_verbose("AFTER DECODE\n");
  csv_dump(&csv);
  csv_clean(&csv);
  log_verbose("Mem: %ld\n", get_memory_usage(getpid()));
}
#endif
