#################################################
# set SWAT directory location
AC_ARG_WITH(swatdir,
[  --with-swatdir=DIR      Where to put SWAT files ($ac_default_prefix/swat)],
[ case "$withval" in
  yes|no)
  #
  # Just in case anybody does it
  #
    AC_MSG_WARN([--with-swatdir called without argument - will use default])
  ;;
  * )
    swatdir="$withval"
    ;;
  esac])

AC_SUBST(swatdir)
