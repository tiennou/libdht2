#!/bin/sh
LIBTOOLIZE=libtoolize
SYSNAME=`uname`
if [ "x$SYSNAME" = "xDarwin" ] ; then
  LIBTOOLIZE=glibtoolize
fi
aclocal && \
	autoheader && \
	$LIBTOOLIZE --force && \
	autoconf && \
	automake --add-missing --copy
