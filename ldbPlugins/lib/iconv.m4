dnl # ICONV/CHARSET subsystem

ICONV_LOCATION=standard
LOOK_DIRS="/usr /usr/local /sw"
AC_ARG_WITH(libiconv,
[  --with-libiconv=BASEDIR Use libiconv in BASEDIR/lib and BASEDIR/include (default=auto) ],
[
  if test "$withval" = "no" ; then
    AC_MSG_ERROR(I won't take no for an answer)
  else
     if test "$withval" != "yes" ; then
        LOOK_DIRS="$withval $LOOK_DIRS"
     fi
  fi
])

ICONV_FOUND="no"
for i in $LOOK_DIRS ; do
    save_LIBS=$LIBS
    save_LDFLAGS=$LDFLAGS
    save_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="-I$i/include"
    LDFLAGS="-L$i/lib"
    LIBS=
    export LDFLAGS LIBS CPPFLAGS
dnl Try to find iconv(3)
    jm_ICONV($i)

    CPPFLAGS=$save_CPPFLAGS
    if test -n "$ICONV_FOUND" ; then
        LDFLAGS=$save_LDFLAGS
        LIB_ADD_DIR(LDFLAGS, "$i/lib")
        CFLAGS_ADD_DIR(CPPFLAGS, "$i/include")
        LIBS="$save_LIBS $LIBS"
        ICONV_LOCATION=$i
        export LDFLAGS LIBS CPPFLAGS
        break
    else
	LDFLAGS=$save_LDFLAGS
        LIBS=$save_LIBS
        export LDFLAGS LIBS CPPFLAGS
    fi
done

############
# check for iconv in libc
AC_CACHE_CHECK([for working iconv],samba_cv_HAVE_NATIVE_ICONV,[
AC_TRY_RUN([
#include <iconv.h>
main() {
       iconv_t cd = iconv_open("ASCII", "UCS-2LE");
       if (cd == 0 || cd == (iconv_t)-1) return -1;
       return 0;
}
],
samba_cv_HAVE_NATIVE_ICONV=yes,samba_cv_HAVE_NATIVE_ICONV=no,samba_cv_HAVE_NATIVE_ICONV=cross)])
if test x"$samba_cv_HAVE_NATIVE_ICONV" = x"yes"; then
    AC_DEFINE(HAVE_NATIVE_ICONV,1,[Whether to use native iconv])
fi

if test x"$ICONV_FOUND" = x"no" -o x"$samba_cv_HAVE_NATIVE_ICONV" != x"yes" ; then
    AC_MSG_WARN([Sufficient support for iconv function was not found. 
    Install libiconv from http://freshmeat.net/projects/libiconv/ for better charset compatibility!])
fi

SMB_SUBSYSTEM(CHARSET,lib/iconv.o,lib/charcnv.o,[${TMP_CHARSET_LIBS}])
