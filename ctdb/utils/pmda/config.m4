AC_ARG_ENABLE(pmda, 
AS_HELP_STRING([--enable-pmda], [Turn on PCP pmda support (default=no)]))

HAVE_PMDA=no

if eval "test x$enable_pmda = xyes"; then
	HAVE_PMDA=yes

	AC_CHECK_HEADERS(pcp/pmapi.h pcp/impl.h pcp/pmda.h, [],
	[AC_MSG_ERROR([Missing PCP pmda headers])],
	[[#ifdef HAVE_PCP_PMAPI_H
	# include <pcp/pmapi.h>
	#endif
	#ifdef HAVE_PCP_IMPL_H
	# include <pcp/impl.h>
	#endif
	#ifdef HAVE_PCP_PMDA_H
	# include <pcp/pmda.h>
	#endif
	]])
fi

if test x"$HAVE_PMDA" = x"yes"; then
    CTDB_PMDA=bin/pmdactdb
    CTDB_PMDA_INSTALL=install_pmda
else
    CTDB_PMDA=
    CTDB_PMDA_INSTALL=
fi

AC_SUBST(CTDB_PMDA)
AC_SUBST(CTDB_PMDA_INSTALL)
