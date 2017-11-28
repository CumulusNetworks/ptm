# Copyright 2016,2017 Cumulus Networks, Inc. All rights reserved.
#
# This file is licensed to You under the Eclipse Public License (EPL);
# You may not use this file except in compliance with the License. You
# may obtain a copy of the License at
# http://www.opensource.org/licenses/eclipse-1.0.php

AM_CPPFLAGS = -I../log

lib_LTLIBRARIES = libptm.la
include_HEADERS = csv.h ptm_lib.h

libptm_la_SOURCES = csv.c ptm_lib.c

# -version-info format is `current`:`revision`:`age`. For more details, see:
#   https://www.sourceware.org/autobook/autobook/autobook_61.html#Library-Versioning
#
# -version-number could be computed from -version-info, mostly major
# is `current` - `age`, minor is `age` and revision is `revision' and
# major.minor should be used when updaing libptm.sym.

libptm_la_LDFLAGS = \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-Wl,--version-script=libptm.sym

pkgconfig_DATA = libptm.pc

TEMPLATES  = libptm.pc
EXTRA_DIST = libptm.pc.in libptm.sym
CLEANFILES = $(TEMPLATES)
