# Copyright 2016,2017 Cumulus Networks, Inc. All rights reserved.
#
# This file is licensed to You under the Eclipse Public License (EPL);
# You may not use this file except in compliance with the License. You
# may obtain a copy of the License at
# http://www.opensource.org/licenses/eclipse-1.0.php
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_define([libptm_lt_current],    [3])
m4_define([libptm_lt_revision],   [0])
m4_define([libptm_lt_age],        [0])

AC_PREREQ([2.69])
AC_INIT([ptm], [3.0], [BUG-REPORT-ADDRESS])
#AM_INIT_AUTOMAKE(ptmd, 3.0)
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AC_CONFIG_MACRO_DIR([m4])
AC_C_BIGENDIAN
AC_CONFIG_SRCDIR([src/ptm_conf.h])
AC_CONFIG_HEADERS([config.h])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_ARG_WITH([pkgconfigdir], AS_HELP_STRING([--with-pkgconfigdir=PATH],
	[Path to the pkgconfig directory [[LIBDIR/pkgconfig]]]),
	[pkgconfigdir="$withval"], [pkgconfigdir='$(libdir)/pkgconfig'])
AC_SUBST([pkgconfigdir])

LT_CURRENT=libptm_lt_current
AC_SUBST(LT_CURRENT)
LT_REVISION=libptm_lt_revision
AC_SUBST(LT_REVISION)
LT_AGE=libptm_lt_age
AC_SUBST(LT_AGE)

#Configure libtool
LT_INIT

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LN_S

AM_PATH_PYTHON([2.7],,AC_MSG_ERROR("Python required for building"))

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h graphviz/cgraph.h lldpctl.h], ,AC_MSG_ERROR("Required header files not found"))

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atexit clock_gettime gethostname gettimeofday memset realpath select socket strchr strdup strerror strpbrk strstr])

AC_CHECK_LIB(cgraph,agopen)
AC_CHECK_LIB(cgraph,agfstin)
AC_CHECK_LIB(cgraph,agfstout)
AC_CHECK_LIB(lldpctl, lldpctl_atom_dec_ref)
AC_CHECK_LIB(lldpctl, lldpctl_process_conn_buffer, [], AC_MSG_ERROR([Need LLDPD > 0.7.10]))

AC_OUTPUT(Makefile lib/log/Makefile lib/ptmlib/Makefile lib/ptmlib/libptm.pc src/Makefile)
