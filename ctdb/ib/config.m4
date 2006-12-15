AC_ARG_ENABLE(--enable-infiniband, 
[  --enable-infiniband         Turn on infiniband support (default=no)])

HAVE_INFINIBAND=no

if eval "test x$enable_infiniband = xyes"; then
        AC_DEFINE(USE_INFINIBAND,1,[Use infiniband])
	HAVE_INFINIBAND=yes

	INFINIBAND_WRAPPER_OBJ="ib/ibwrapper.o"
	INFINIBAND_LIBS="-lrdmacm -libverbs"
	INFINIBAND_BINS="bin/ibwrapper_test"
fi

AC_SUBST(HAVE_INFINIBAND)
AC_SUBST(INFINIBAND_WRAPPER_OBJ)
AC_SUBST(INFINIBAND_LIBS)
AC_SUBST(INFINIBAND_BINS)
