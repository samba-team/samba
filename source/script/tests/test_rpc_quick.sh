#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-ALTERCONTEXT RPC-JOIN RPC-ECHO RPC-SCHANNEL RPC-NETLOGON RPC-UNIXINFO RPC-HANDLES"
ncacn_ip_tcp_tests="RPC-ALTERCONTEXT RPC-JOIN RPC-ECHO RPC-HANDLES"
ncalrpc_tests="RPC-ECHO"

incdir=`dirname $0`
. $incdir/test_functions.sh

for bindoptions in seal,padcheck $VALIDATE bigendian; do
 for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
   case $transport in
	 ncalrpc) tests=$ncalrpc_tests ;;
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
   esac
   for t in $tests; do
    name="$t on $transport with $bindoptions"
    plantest "$name" dc $VALGRIND bin/smbtorture $TORTURE_OPTIONS $transport:"\$SERVER[$bindoptions]" -U"\$USERNAME"%"\$PASSWORD" -W \$DOMAIN $t "$*"
   done
 done
done
