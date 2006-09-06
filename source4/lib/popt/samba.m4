m4_include(lib/popt/libpopt.m4)
SMB_SUBSYSTEM(LIBPOPT,
	[lib/popt/findme.o lib/popt/popt.o lib/popt/poptconfig.o lib/popt/popthelp.o lib/popt/poptparse.o], [], [-I$srcdir/lib/popt])
