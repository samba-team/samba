dnl AC_VALIDATE_CACHE_SYSTEM_TYPE[(cmd)]
dnl if the cache file is inconsistent with the current host,
dnl target and build system types, execute CMD or print a default
dnl error message.
AC_DEFUN(AC_VALIDATE_CACHE_SYSTEM_TYPE, [
    AC_REQUIRE([AC_CANONICAL_SYSTEM])
    AC_MSG_CHECKING([config.cache system type])
    if { test x"${ac_cv_host_system_type+set}" = x"set" &&
         test x"$ac_cv_host_system_type" != x"$host"; } ||
       { test x"${ac_cv_build_system_type+set}" = x"set" &&
         test x"$ac_cv_build_system_type" != x"$build"; } ||
       { test x"${ac_cv_target_system_type+set}" = x"set" &&
         test x"$ac_cv_target_system_type" != x"$target"; }; then
	AC_MSG_RESULT([different])
	ifelse($#, 1, [$1],
		[AC_MSG_ERROR(["you must remove config.cache and restart configure"])])
    else
	AC_MSG_RESULT([same])
    fi
    ac_cv_host_system_type="$host"
    ac_cv_build_system_type="$build"
    ac_cv_target_system_type="$target"
])


dnl test whether dirent has a d_off member
AC_DEFUN(AC_DIRENT_D_OFF,
[AC_CACHE_CHECK([for d_off in dirent], ac_cv_dirent_d_off,
[AC_TRY_COMPILE([
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>], [struct dirent d; d.d_off;],
ac_cv_dirent_d_off=yes, ac_cv_dirent_d_off=no)])
if test $ac_cv_dirent_d_off = yes; then
  AC_DEFINE(HAVE_DIRENT_D_OFF,1,[Whether dirent has a d_off member])
fi
])


dnl AC_PROG_CC_FLAG(flag)
AC_DEFUN(AC_PROG_CC_FLAG,
[AC_CACHE_CHECK(whether ${CC-cc} accepts -$1, ac_cv_prog_cc_$1,
[echo 'void f(){}' > conftest.c
if test -z "`${CC-cc} -$1 -c conftest.c 2>&1`"; then
  ac_cv_prog_cc_$1=yes
else
  ac_cv_prog_cc_$1=no
fi
rm -f conftest*
])])

dnl see if a declaration exists for a function or variable
dnl defines HAVE_function_DECL if it exists
dnl AC_HAVE_DECL(var, includes)
AC_DEFUN(AC_HAVE_DECL,
[
 AC_CACHE_CHECK([for $1 declaration],ac_cv_have_$1_decl,[
    AC_TRY_COMPILE([$2],[int i = (int)$1],
        ac_cv_have_$1_decl=yes,ac_cv_have_$1_decl=no)])
 if test x"$ac_cv_have_$1_decl" = x"yes"; then
    AC_DEFINE([HAVE_]translit([$1], [a-z], [A-Z])[_DECL],1,[Whether $1() is available])
 fi
])


dnl check for a function in a library, but don't
dnl keep adding the same library to the LIBS variable.
dnl AC_LIBTESTFUNC(lib,func)
AC_DEFUN(AC_LIBTESTFUNC,
[case "$LIBS" in
  *-l$1*) AC_CHECK_FUNCS($2) ;;
  *) AC_CHECK_LIB($1, $2) 
     AC_CHECK_FUNCS($2)
  ;;
  esac
])

dnl Define an AC_DEFINE with ifndef guard.
dnl AC_N_DEFINE(VARIABLE [, VALUE])
define(AC_N_DEFINE,
[cat >> confdefs.h <<\EOF
[#ifndef] $1
[#define] $1 ifelse($#, 2, [$2], $#, 3, [$2], 1)
[#endif]
EOF
])

dnl Add an #include
dnl AC_ADD_INCLUDE(VARIABLE)
define(AC_ADD_INCLUDE,
[cat >> confdefs.h <<\EOF
[#include] $1
EOF
])

dnl Copied from libtool.m4
AC_DEFUN(AC_PROG_LD_GNU,
[AC_CACHE_CHECK([if the linker ($LD) is GNU ld], ac_cv_prog_gnu_ld,
[# I'd rather use --version here, but apparently some GNU ld's only accept -v.
if $LD -v 2>&1 </dev/null | egrep '(GNU|with BFD)' 1>&5; then
  ac_cv_prog_gnu_ld=yes
else
  ac_cv_prog_gnu_ld=no
fi])
])

# Configure paths for LIBXML2
# Toshio Kuratomi 2001-04-21
# Adapted from:
# Configure paths for GLIB
# Owen Taylor     97-11-3

dnl AM_PATH_XML2([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for XML, and define XML_CFLAGS and XML_LIBS
dnl
AC_DEFUN(AM_PATH_XML2,[ 
AC_ARG_WITH(xml-prefix,
            [  --with-xml-prefix=PFX   Prefix where libxml is installed (optional)],
            xml_config_prefix="$withval", xml_config_prefix="")
AC_ARG_WITH(xml-exec-prefix,
            [  --with-xml-exec-prefix=PFX Exec prefix where libxml is installed (optional)],
            xml_config_exec_prefix="$withval", xml_config_exec_prefix="")
AC_ARG_ENABLE(xmltest,
              [  --disable-xmltest       Do not try to compile and run a test LIBXML program],,
              enable_xmltest=yes)

  if test x$xml_config_exec_prefix != x ; then
     xml_config_args="$xml_config_args --exec-prefix=$xml_config_exec_prefix"
     if test x${XML2_CONFIG+set} != xset ; then
        XML2_CONFIG=$xml_config_exec_prefix/bin/xml2-config
     fi
  fi
  if test x$xml_config_prefix != x ; then
     xml_config_args="$xml_config_args --prefix=$xml_config_prefix"
     if test x${XML2_CONFIG+set} != xset ; then
        XML2_CONFIG=$xml_config_prefix/bin/xml2-config
     fi
  fi

  AC_PATH_PROG(XML2_CONFIG, xml2-config, no)
  min_xml_version=ifelse([$1], ,2.0.0,[$1])
  AC_MSG_CHECKING(for libxml - version >= $min_xml_version)
  no_xml=""
  if test "$XML2_CONFIG" = "no" ; then
    no_xml=yes
  else
    XML_CFLAGS=`$XML2_CONFIG $xml_config_args --cflags`
    XML_LIBS=`$XML2_CONFIG $xml_config_args --libs`
    xml_config_major_version=`$XML2_CONFIG $xml_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    xml_config_minor_version=`$XML2_CONFIG $xml_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    xml_config_micro_version=`$XML2_CONFIG $xml_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`
    if test "x$enable_xmltest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $XML_CFLAGS"
      LIBS="$XML_LIBS $LIBS"
dnl
dnl Now check if the installed libxml is sufficiently new.
dnl (Also sanity checks the results of xml2-config to some extent)
dnl
      rm -f conf.xmltest
      AC_TRY_RUN([
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libxml/xmlversion.h>

int 
main()
{
  int xml_major_version, xml_minor_version, xml_micro_version;
  int major, minor, micro;
  char *tmp_version;

  system("touch conf.xmltest");

  /* Capture xml2-config output via autoconf/configure variables */
  /* HP/UX 9 (%@#!) writes to sscanf strings */
  tmp_version = (char *)strdup("$min_xml_version");
  if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
     printf("%s, bad version string from xml2-config\n", "$min_xml_version");
     exit(1);
   }
   free(tmp_version);

   /* Capture the version information from the header files */
   tmp_version = (char *)strdup(LIBXML_DOTTED_VERSION);
   if (sscanf(tmp_version, "%d.%d.%d", &xml_major_version, &xml_minor_version, &xml_micro_version) != 3) {
     printf("%s, bad version string from libxml includes\n", "LIBXML_DOTTED_VERSION");
     exit(1);
   }
   free(tmp_version);

 /* Compare xml2-config output to the libxml headers */
  if ((xml_major_version != $xml_config_major_version) ||
      (xml_minor_version != $xml_config_minor_version) ||
      (xml_micro_version != $xml_config_micro_version))
    {
      printf("*** libxml header files (version %d.%d.%d) do not match\n",
         xml_major_version, xml_minor_version, xml_micro_version);
      printf("*** xml2-config (version %d.%d.%d)\n",
         $xml_config_major_version, $xml_config_minor_version, $xml_config_micro_version);
      return 1;
    } 
/* Compare the headers to the library to make sure we match */
  /* Less than ideal -- doesn't provide us with return value feedback, 
   * only exits if there's a serious mismatch between header and library.
   */
    LIBXML_TEST_VERSION;

    /* Test that the library is greater than our minimum version */
    if ((xml_major_version > major) ||
        ((xml_major_version == major) && (xml_minor_version > minor)) ||
        ((xml_major_version == major) && (xml_minor_version == minor) &&
        (xml_micro_version >= micro)))
      {
        return 0;
       }
     else
      {
        printf("\n*** An old version of libxml (%d.%d.%d) was found.\n",
               xml_major_version, xml_minor_version, xml_micro_version);
        printf("*** You need a version of libxml newer than %d.%d.%d. The latest version of\n",
           major, minor, micro);
        printf("*** libxml is always available from ftp://ftp.xmlsoft.org.\n");
        printf("***\n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the xml2-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBXML, but you can also set the XML2_CONFIG environment to point to the\n");
        printf("*** correct copy of xml2-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
    }
  return 1;
}
],, no_xml=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi

  if test "x$no_xml" = x ; then
     AC_MSG_RESULT(yes (version $xml_config_major_version.$xml_config_minor_version.$xml_config_micro_version))
     ifelse([$2], , :, [$2])     
  else
     AC_MSG_RESULT(no)
     if test "$XML2_CONFIG" = "no" ; then
       echo "*** The xml2-config script installed by LIBXML could not be found"
       echo "*** If libxml was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the XML2_CONFIG environment variable to the"
       echo "*** full path to xml2-config."
     else
       if test -f conf.xmltest ; then
        :
       else
          echo "*** Could not run libxml test program, checking why..."
          CFLAGS="$CFLAGS $XML_CFLAGS"
          LIBS="$LIBS $XML_LIBS"
          AC_TRY_LINK([
#include <libxml/xmlversion.h>
#include <stdio.h>
],      [ LIBXML_TEST_VERSION; return 0;],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBXML or finding the wrong"
          echo "*** version of LIBXML. If it is not finding LIBXML, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBXML was incorrectly installed"
          echo "*** or that you have moved LIBXML since it was installed. In the latter case, you"
          echo "*** may want to edit the xml2-config script: $XML2_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi

     XML_CFLAGS=""
     XML_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(XML_CFLAGS)
  AC_SUBST(XML_LIBS)
  rm -f conf.xmltest
])

# =========================================================================
# AM_PATH_MYSQL : MySQL library

dnl AM_PATH_MYSQL([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for MYSQL, and define MYSQL_CFLAGS and MYSQL_LIBS
dnl
AC_DEFUN(AM_PATH_MYSQL,
[dnl
dnl Get the cflags and libraries from the mysql_config script
dnl
AC_ARG_WITH(mysql-prefix,[  --with-mysql-prefix=PFX   Prefix where MYSQL is installed (optional)],
            mysql_prefix="$withval", mysql_prefix="")
AC_ARG_WITH(mysql-exec-prefix,[  --with-mysql-exec-prefix=PFX Exec prefix where MYSQL is installed (optional)],
            mysql_exec_prefix="$withval", mysql_exec_prefix="")
AC_ARG_ENABLE(mysqltest, [  --disable-mysqltest       Do not try to compile and run a test MYSQL program],
         , enable_mysqltest=yes)

  if test x$mysql_exec_prefix != x ; then
     mysql_args="$mysql_args --exec-prefix=$mysql_exec_prefix"
     if test x${MYSQL_CONFIG+set} != xset ; then
        MYSQL_CONFIG=$mysql_exec_prefix/bin/mysql_config
     fi
  fi
  if test x$mysql_prefix != x ; then
     mysql_args="$mysql_args --prefix=$mysql_prefix"
     if test x${MYSQL_CONFIG+set} != xset ; then
        MYSQL_CONFIG=$mysql_prefix/bin/mysql_config
     fi
  fi

  AC_REQUIRE([AC_CANONICAL_TARGET])
  AC_PATH_PROG(MYSQL_CONFIG, mysql_config, no)
  min_mysql_version=ifelse([$1], ,0.11.0,$1)
  AC_MSG_CHECKING(for MYSQL - version >= $min_mysql_version)
  no_mysql=""
  if test "$MYSQL_CONFIG" = "no" ; then
    no_mysql=yes
  else
    MYSQL_CFLAGS=`$MYSQL_CONFIG $mysqlconf_args --cflags | sed -e "s/'//g"`
    MYSQL_LIBS=`$MYSQL_CONFIG $mysqlconf_args --libs | sed -e "s/'//g"`

    mysql_major_version=`$MYSQL_CONFIG $mysql_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    mysql_minor_version=`$MYSQL_CONFIG $mysql_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    mysql_micro_version=`$MYSQL_CONFIG $mysql_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`
    if test "x$enable_mysqltest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $MYSQL_CFLAGS"
      LIBS="$LIBS $MYSQL_LIBS"
dnl
dnl Now check if the installed MYSQL is sufficiently new. (Also sanity
dnl checks the results of mysql_config to some extent
dnl
      rm -f conf.mysqltest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

char*
my_strdup (char *str)
{
  char *new_str;

  if (str)
    {
      new_str = (char *)malloc ((strlen (str) + 1) * sizeof(char));
      strcpy (new_str, str);
    }
  else
    new_str = NULL;

  return new_str;
}

int main (int argc, char *argv[])
{
int major, minor, micro;
  char *tmp_version;

  /* This hangs on some systems (?)
  system ("touch conf.mysqltest");
  */
  { FILE *fp = fopen("conf.mysqltest", "a"); if ( fp ) fclose(fp); }

  /* HP/UX 9 (%@#!) writes to sscanf strings */
  tmp_version = my_strdup("$min_mysql_version");
  if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
     printf("%s, bad version string\n", "$min_mysql_version");
     exit(1);
   }

   if (($mysql_major_version > major) ||
      (($mysql_major_version == major) && ($mysql_minor_version > minor)) ||
      (($mysql_major_version == major) && ($mysql_minor_version == minor) && ($mysql_micro_version >= micro)))
    {
      return 0;
    }
  else
    {
      printf("\n*** 'mysql_config --version' returned %d.%d.%d, but the minimum version\n", $mysql_major_version, $mysql_minor_version, $mysql_micro_version);
      printf("*** of MYSQL required is %d.%d.%d. If mysql_config is correct, then it is\n", major, minor, micro);
      printf("*** best to upgrade to the required version.\n");
      printf("*** If mysql_config was wrong, set the environment variable MYSQL_CONFIG\n");
      printf("*** to point to the correct copy of mysql_config, and remove the file\n");
      printf("*** config.cache before re-running configure\n");
      return 1;
    }
}

],, no_mysql=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_mysql" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     AC_MSG_RESULT(no)
     if test "$MYSQL_CONFIG" = "no" ; then
       echo "*** The mysql_config script installed by MYSQL could not be found"
       echo "*** If MYSQL was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the MYSQL_CONFIG environment variable to the"
       echo "*** full path to mysql_config."
     else
       if test -f conf.mysqltest ; then
        :
       else
          echo "*** Could not run MYSQL test program, checking why..."
          CFLAGS="$CFLAGS $MYSQL_CFLAGS"
          LIBS="$LIBS $MYSQL_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <mysql.h>

int main(int argc, char *argv[])
{ return 0; }
#undef  main
#define main K_and_R_C_main
],      [ return 0; ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding MYSQL or finding the wrong"
          echo "*** version of MYSQL. If it is not finding MYSQL, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
    echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means MYSQL was incorrectly installed"
          echo "*** or that you have moved MYSQL since it was installed. In the latter case, you"
          echo "*** may want to edit the mysql_config script: $MYSQL_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     MYSQL_CFLAGS=""
     MYSQL_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(MYSQL_CFLAGS)
  AC_SUBST(MYSQL_LIBS)
  rm -f conf.mysqltest
])

dnl Removes -I/usr/include/? from given variable
AC_DEFUN(CFLAGS_REMOVE_USR_INCLUDE,[
  ac_new_flags=""
  for i in [$]$1; do
    case [$]i in
    -I/usr/include|-I/usr/include/) ;;
    *) ac_new_flags="[$]ac_new_flags [$]i" ;;
    esac
  done
  $1=[$]ac_new_flags
])
    
dnl Removes -L/usr/lib/? from given variable
AC_DEFUN(LIB_REMOVE_USR_LIB,[
  ac_new_flags=""
  for i in [$]$1; do
    case [$]i in
    -L/usr/lib|-L/usr/lib/) ;;
    *) ac_new_flags="[$]ac_new_flags [$]i" ;;
    esac
  done
  $1=[$]ac_new_flags
])

dnl From Bruno Haible.

AC_DEFUN(jm_ICONV,
[
  dnl Some systems have iconv in libc, some have it in libiconv (OSF/1 and
  dnl those with the standalone portable libiconv installed).
  AC_MSG_CHECKING(for iconv in $1)
    jm_cv_func_iconv="no"
    jm_cv_lib_iconv=no
    jm_cv_giconv=no
    AC_TRY_LINK([#include <stdlib.h>
#include <giconv.h>],
      [iconv_t cd = iconv_open("","");
       iconv(cd,NULL,NULL,NULL,NULL);
       iconv_close(cd);],
      jm_cv_func_iconv=yes
      jm_cv_giconv=yes)

    if test "$jm_cv_func_iconv" != yes; then
      AC_TRY_LINK([#include <stdlib.h>
#include <iconv.h>],
        [iconv_t cd = iconv_open("","");
         iconv(cd,NULL,NULL,NULL,NULL);
         iconv_close(cd);],
        jm_cv_func_iconv=yes)

        if test "$jm_cv_lib_iconv" != yes; then
          jm_save_LIBS="$LIBS"
          LIBS="$LIBS -lgiconv"
          AC_TRY_LINK([#include <stdlib.h>
#include <giconv.h>],
            [iconv_t cd = iconv_open("","");
             iconv(cd,NULL,NULL,NULL,NULL);
             iconv_close(cd);],
            jm_cv_lib_iconv=yes
            jm_cv_func_iconv=yes
            jm_cv_giconv=yes)
          LIBS="$jm_save_LIBS"

      if test "$jm_cv_func_iconv" != yes; then
        jm_save_LIBS="$LIBS"
        LIBS="$LIBS -liconv"
        AC_TRY_LINK([#include <stdlib.h>
#include <iconv.h>],
          [iconv_t cd = iconv_open("","");
           iconv(cd,NULL,NULL,NULL,NULL);
           iconv_close(cd);],
          jm_cv_lib_iconv=yes
          jm_cv_func_iconv=yes)
        LIBS="$jm_save_LIBS"
        fi
      fi
    fi

  if test "$jm_cv_func_iconv" = yes; then
    if test "$jm_cv_giconv" = yes; then
      AC_DEFINE(HAVE_GICONV, 1, [What header to include for iconv() function: giconv.h])
      AC_MSG_RESULT(yes)
      ICONV_FOUND=yes
    else
      AC_DEFINE(HAVE_ICONV, 1, [What header to include for iconv() function: iconv.h])
      AC_MSG_RESULT(yes)
      ICONV_FOUND=yes
    fi
  else
    AC_MSG_RESULT(no)
  fi
  if test "$jm_cv_lib_iconv" = yes; then
    if test "$jm_cv_giconv" = yes; then
      LIBS="$LIBS -lgiconv"
    else
      LIBS="$LIBS -liconv"
    fi
  fi
])

dnl CFLAGS_ADD_DIR(CFLAGS, $INCDIR)
dnl This function doesn't add -I/usr/include into CFLAGS
AC_DEFUN(CFLAGS_ADD_DIR,[
if test "$2" != "/usr/include" ; then
    $1="$$1 -I$2"
fi
])

dnl LIB_ADD_DIR(LDFLAGS, $LIBDIR)
dnl This function doesn't add -L/usr/lib into LDFLAGS
AC_DEFUN(LIB_ADD_DIR,[
if test "$2" != "/usr/lib" ; then
    $1="$$1 -L$2"
fi
])

dnl AC_ENABLE_SHARED - implement the --enable-shared flag
dnl Usage: AC_ENABLE_SHARED[(DEFAULT)]
dnl   Where DEFAULT is either `yes' or `no'.  If omitted, it defaults to
dnl   `yes'.
AC_DEFUN([AC_ENABLE_SHARED],
[define([AC_ENABLE_SHARED_DEFAULT], ifelse($1, no, no, yes))dnl
AC_ARG_ENABLE(shared,
changequote(<<, >>)dnl
<<  --enable-shared[=PKGS]    build shared libraries [default=>>AC_ENABLE_SHARED_DEFAULT],
changequote([, ])dnl
[p=${PACKAGE-default}
case $enableval in
yes) enable_shared=yes ;;
no) enable_shared=no ;;
*)
  enable_shared=no
  # Look at the argument we got.  We use all the common list separators.
  IFS="${IFS=   }"; ac_save_ifs="$IFS"; IFS="${IFS}:,"
  for pkg in $enableval; do
    if test "X$pkg" = "X$p"; then
      enable_shared=yes
    fi

  done
  IFS="$ac_save_ifs"
  ;;
esac],
enable_shared=AC_ENABLE_SHARED_DEFAULT)dnl
])

dnl AC_ENABLE_STATIC - implement the --enable-static flag
dnl Usage: AC_ENABLE_STATIC[(DEFAULT)]
dnl   Where DEFAULT is either `yes' or `no'.  If omitted, it defaults to
dnl   `yes'.
AC_DEFUN([AC_ENABLE_STATIC],
[define([AC_ENABLE_STATIC_DEFAULT], ifelse($1, no, no, yes))dnl
AC_ARG_ENABLE(static,
changequote(<<, >>)dnl
<<  --enable-static[=PKGS]    build static libraries [default=>>AC_ENABLE_STATIC_DEFAULT],
changequote([, ])dnl
[p=${PACKAGE-default}
case $enableval in
yes) enable_static=yes ;;
no) enable_static=no ;;
*)
  enable_static=no
  # Look at the argument we got.  We use all the common list separators.
  IFS="${IFS=   }"; ac_save_ifs="$IFS"; IFS="${IFS}:,"
  for pkg in $enableval; do
    if test "X$pkg" = "X$p"; then
      enable_static=yes
    fi
  done
  IFS="$ac_save_ifs"
  ;;
esac],
enable_static=AC_ENABLE_STATIC_DEFAULT)dnl
])

dnl AC_DISABLE_STATIC - set the default static flag to --disable-static
AC_DEFUN([AC_DISABLE_STATIC],
[AC_BEFORE([$0],[AC_LIBTOOL_SETUP])dnl
AC_ENABLE_STATIC(no)])
