m4_include(lib/popt/libpopt.m4)

if test x"$POPTOBJ" = "x"; then
	echo "LIBPOPT as EXT_LIB" 
	SMB_EXT_LIB(LIBPOPT, [${POPT_LIBS}])
	SMB_ENABLE(LIBPOPT,YES)
else
	echo "LIBPOPT as SUBSYSTEM" 
	SMB_SUBSYSTEM(LIBPOPT,
	[lib/popt/findme.o lib/popt/popt.o lib/popt/poptconfig.o lib/popt/popthelp.o lib/popt/poptparse.o], [], [-Ilib/popt])
fi

