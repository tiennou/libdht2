# CHECK_PACKAGE(package-name, cflags, libs, additional-locations, additional-subpaths)

AC_DEFUN([CHECK_PACKAGE],
[
AC_MSG_CHECKING([for $1])
AC_ARG_WITH([$1],
	AS_HELP_STRING([--with-${1}=DIR], [use $1 in DIR]),
		[ case "$withval" in
			yes|no)
				AC_ERROR([You should provide a path, not yes/no])
			;;
			*)
				supplieddir=$withval
			;;
		esac]
	)dnl
	for dir in $supplieddir $4 /usr/local /usr; do
		for subpath in $5 ""; do
			if test -f "$dir/include/$subpath/$1.h"; then
				found_pkg="yes"
				$1_CFLAGS="-I$dir/include/$subpath ${CFLAGS}"
			break
			fi
		done
	done
	if test x_$found_pkg != x_yes; then
		AC_MSG_RESULT(Cannot find $1 libraries)
	else
		if test "x_${LIBS}" = x_; then
			$1_LIBS=-l$1
		else
			$1_LIBS=$3
		fi
		$1_LDFLAGS="-L$dir/lib"
		AC_MSG_RESULT($dir)
	fi
	AC_SUBST($1_CFLAGS)
	AC_SUBST($1_LDFLAGS)
	AC_SUBST($1_LIBS)
])dnl
