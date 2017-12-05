# Copyright 2016,2017 Cumulus Networks, Inc. All rights reserved.
#
# This file is licensed to You under the Eclipse Public License (EPL);
# You may not use this file except in compliance with the License. You
# may obtain a copy of the License at
# http://www.opensource.org/licenses/eclipse-1.0.php

PTMD_VERSION=3.0
AM_CFLAGS = -Wno-enum-compare -Wno-unused-result -std=gnu99 -Wall -Werror -g -O0 -DPTMD_VERSION=\"$(PTMD_VERSION)\"
AM_CPPFLAGS = -I../lib/ -I../lib/ptmlib -Ihash -Igraph
AM_LDFLAGS = -L../lib/ptmlib -L/usr/lib -llldpctl -lcgraph -lrt

sbin_PROGRAMS = ptmd
sbin_SCRIPTS  = ptmctl

ptmd_LDADD = ../lib/ptmlib/.libs/libptm.a
ptmd_SOURCES = ptm_lldp.c ptm_ctl.c ptm_event.c ptm_conf.c ptm_timer.c ptm_bfd.c ptm_nbr.c ptm_quagga.c ptm_ipaddr.c ptm_util.c ptm_netlink.c
noinst_HEADERS = \
	ptm_conf.h ptm_lldp.h ptm_event.h ptm_ctl.h ptm_timer.h ptm_bfd.h ptm_nbr.h ptm_quagga.h ptm_quagga_if.h ptm_ipaddr.h ptm_util.h ptm_netlink.h graph/cdt.h graph/cgraph.h

EXTRA_DIST = ptmctl.py

ptmctl: ptmctl.py
	cp ptmctl.py ptmctl
	chmod +x ptmctl

create-symbolic-links:
	echo "making symbolic links" \
	../scripts/create-sym-links.sh

create-man-pages:
	echo "Making manpages" \
	../scripts/deb-rst2man.sh .
