PTMD_VERSION="2.0"
AM_CPPFLAGS = -I../lib -Igraph -Ihash
AM_CFLAGS = -Wno-enum-compare -std=gnu99 -Wall -Werror -g -O0 -DPTMD_VERSION=\"$PTMD_VERSION\"
AM_LDFLAGS = -L../lib -llldpctl -lcgraph -lrt -lcdt

sbin_PROGRAMS = ptmd
sbin_SCRIPTS  = ptmctl

ptmd_LDADD = ../lib/libptmdep.a
ptmd_SOURCES=ptm_lldp.c ptm_ctl.c ptm_event.c ptm_conf.c ptm_msg.c ptm_timer.c ptm_bfd.c ptm_nbr.c ptm_quagga.c
noinst_HEADERS = \
	ptm_conf.h ptm_lldp.h ptm_event.h ptm_ctl.h ptm_timer.h ptm_msg.h ptm_bfd.h ptm_nbr.h ptm_quagga.h

EXTRA_DIST = ptmctl.py

ptmctl: ptmctl.py
	cp ptmctl.py ptmctl
	chmod +x ptmctl

