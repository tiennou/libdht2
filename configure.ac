# configure.in for libdht
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libdht],[0.1],[http://code.google.com/p/libdht2/issues/entry])
AC_CONFIG_SRCDIR(src/dht.h)
AC_CONFIG_HEADER([config.h])
AC_CONFIG_LIBOBJ_DIR(compat)

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
# Checks for libcrypto
AC_ARG_WITH(libcrypto,
[  --with-libcrypto=DIR      use libcrypto in DIR],
[ case "$withval" in
  yes|no)
    AC_MSG_RESULT(no)
    ;;
  *)
    AC_MSG_RESULT($withval)
    LIBS=$LIBS:$withval/lib
    ;;
  esac ])
AC_CHECK_LIB([crypto], [SHA1_Init], [], [AC_ERROR(libcrypto not found)])
AC_CHECK_HEADERS([ssl/sha.h openssl/sha.h], break)

# Checks for libevent
AC_ARG_WITH(libevent,
[  --with-libevent=DIR      use libevent in DIR],
[ case "$withval" in
  yes|no)
    AC_MSG_RESULT(no)
    ;;
  *)
    AC_MSG_RESULT($withval)
    LIBS=$LIBS:$withval/lib
    ;;
  esac ])
AC_CHECK_LIB([event], [event_init], [], [AC_ERROR(libevent not found)])
AC_CHECK_HEADERS([event.h], break, [AC_ERROR(event.h header not found)])

# Checks for libdnet
AC_ARG_WITH(libdnet,
[  --with-libdnet=DIR      use libdnet in DIR],
[ case "$withval" in
  yes|no)
     AC_ERROR([Please specify directory containing dnet-config when using --with-libdnet])
    ;;
  *)
    AC_MSG_RESULT($withval)
    PATH=$PATH:$withval
    ;;
  esac ])
AC_PATH_PROG(dnetconfig, dnet-config, "no")

if test "$dnetconfig" = "no"; then
    AC_ERROR(dnet-config not found)
else
    CFLAGS="$CFLAGS `$dnetconfig --cflags`"
    LIBS="$LIBS `$dnetconfig --libs`"
fi

AC_MSG_CHECKING([whether libdnet is a libdumbnet])
if test `echo $DNETLIB | sed -e '/dumb/=;d'`; then
     AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_DUMBNET, 1,
		[Define if our libdnet is a libdumbnet])
     LDFLAGS="compat/libdnet $LDFLAGS"
else
     AC_MSG_RESULT(no)
fi

AC_MSG_NOTICE($CFLAGS)
AC_MSG_NOTICE($LDFLAGS)
AC_MSG_NOTICE($LIBS)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_STAT
AC_CHECK_FUNCS([fchdir getcwd gettimeofday memset mkdir socket strdup strncasecmp SHA1_Init])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 test/Makefile])
AC_OUTPUT
