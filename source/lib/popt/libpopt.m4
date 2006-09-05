dnl find the popt sources. This is meant to work both for 
dnl popt standalone builds, and builds of packages using popt
poptdir=""
for d in "$srcdir" "$srcdir/lib/popt" "$srcdir/popt" "$srcdir/../popt"; do
	if test -f "$d/popt.c"; then
		poptdir="$d"		
		AC_SUBST(poptdir)
		break;
	fi
done
POPTOBJ="popt.o findme.o poptconfig.o popthelp.o poptparse.o"
AC_SUBST(POPTOBJ)

AC_CHECK_HEADERS([float.h alloca.h])
