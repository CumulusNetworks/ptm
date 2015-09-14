#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ptm], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE(ptmd, 1.0)
AC_C_BIGENDIAN
AC_CONFIG_SRCDIR([src/ptm_conf.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_RANLIB

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

AC_OUTPUT(Makefile src/Makefile lib/Makefile)

