dnl Try to find a replacement library
dnl Will define HAVE_REPLACE_H if replace.h can be found
AC_DEFUN([SMB_LIBREPLACE], [
AC_ARG_WITH(libreplace, 
[ --with-libreplace					Specify location to libreplace],
[
 	# Check whether libreplace can actually be found in this location
	if ! test -f "$withval/replace.h"
	then
		AC_MSG_ERROR([Unable to find replace.h in $withval])
	fi
	replacedir=$withval
],
[
	# Check if we can find libreplace in a common location
	for dir in . replace ../replace
	do
		AC_MSG_CHECKING([for libreplace in $dir])
		if test -f "$dir/replace.h"
		then
			replacedir="$dir"
			AC_MSG_RESULT(yes)
			break
		fi
		AC_MSG_RESULT(no)
	done
])

AC_SUBST(REPLACE_LIBS)

if test "$replacedir" != ""
then
	REPLACE_LIBS="$replacedir/libreplace.a"
	CFLAGS="$CFLAGS -I$replacedir"
	AC_DEFINE(HAVE_REPLACE_H, 1, 
		  [Whether replace.h is present and should be used])
fi
])

dnl Try to find the specified functions in the system, or 
dnl in Samba's replacement library. In the future, this may also 
dnl try to find these functions in libroken or GNUlib if libreplace can't be 
dnl found.
AC_DEFUN(SMB_REPLACE_FUNCS, [
		 AC_REQUIRE([SMB_LIBREPLACE])dnl

		 if test -z "$replacedir" || test -f "$replacedir/libreplace.a"
		 then
		 	 LIBS="$LIBS $REPLACE_LIBS"
			 for f in $1
			 do
				AC_CHECK_FUNC($f, [], [
					AC_MSG_ERROR([Unable to find $f in the system. Consider
								 specifying the path to the replacement library])
				])
			 done
		fi
])
