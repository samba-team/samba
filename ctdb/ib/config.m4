AC_ARG_ENABLE(--enable-infiniband, 
[  --enable-infiniband         Turn on infiniband support (default=no)])

HAVE_INFINIBAND=no

if eval "test x$enable_infiniband = xyes"; then
        AC_DEFINE(USE_INFINIBAND,1,[Use infiniband])
	HAVE_INFINIBAND=yes

	INFINIBAND_WRAPPER_OBJ="ib/ibwrapper.o ib/ibw_ctdb.o ib/ibw_ctdb_init.o"
	INFINIBAND_LIBS="-lrdmacm -libverbs"
	INFINIBAND_BINS="tests/bin/ibwrapper_test"

	AC_CHECK_HEADERS(infiniband/verbs.h, [], [
		echo "ERROR: you need infiniband/verbs.h when ib enabled!"
		exit -1])
	AC_CHECK_HEADERS(rdma/rdma_cma.h, [], [
		echo "ERROR: you need rdma/rdma_cma.h when ib enabled!"
		exit -1])
	AC_CHECK_LIB(ibverbs, ibv_create_qp, [], [
		echo "ERROR: you need libibverbs when ib enabled!"
		exit -1])
	AC_CHECK_LIB(rdmacm, rdma_connect, [], [
		echo "ERROR: you need librdmacm when ib enabled!"
		exit -1])
fi

AC_SUBST(HAVE_INFINIBAND)
AC_SUBST(INFINIBAND_WRAPPER_OBJ)
AC_SUBST(INFINIBAND_LIBS)
AC_SUBST(INFINIBAND_BINS)
