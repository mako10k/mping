#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mping], [0.1.3], [mako10k@mk10.org])
AC_CONFIG_SRCDIR([src/mping.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h fcntl.h netdb.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_STRTOD
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime memset select socket strtol])
AC_CONFIG_FILES([Makefile src/Makefile docker/Dockerfile])


AC_OUTPUT
