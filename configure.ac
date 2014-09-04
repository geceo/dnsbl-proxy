#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.0])
AC_INIT([ospow-dnsbl-proxy],[2.0], [gcolangelo@ospow.com])
AM_INIT_AUTOMAKE

#PKG_PROG_PKG_CONFIG(0.1)
# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C_O
AM_PROG_CC_C_O

AC_CONFIG_FILES([src/Makefile conf/Makefile Makefile])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-levent':
AC_CHECK_LIB([event], [main])
# FIXME: Replace `main' with a function in `-lresolv':
AC_CHECK_LIB([resolv], [main])


AC_ARG_ENABLE([static], [AC_HELP_STRING([--enable-static], [Enable static binary])],[],[enable_static=no])
if [[ "$enable_static" = "yes" ]]; then
	CFLAGS="$CFLAGS -static"
fi

PKG_CHECK_MODULES(glib, gthread-2.0 glib-2.0 )
PKG_CHECK_MODULES(pcre, libpcre)
CFLAGS="-Wall -O2 $CFLAGS $glib_CFLAGS $pcre_CFLAGS"
LIBS="$LIBS $LDFLAGS $glib_LIBS $pcre_LIBS"

#AC_OUTPUT
