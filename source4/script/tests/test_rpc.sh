#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-SPOOLSS RPC-SCHANNEL RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND"
ncalrpc_tests="RPC-SCHANNEL RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND"
ncacn_ip_tcp_tests="RPC-SCHANNEL RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND"

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_rpc.sh SERVER USERNAME PASSWORD DOMAIN
EOF
exit 1;
fi

if [ -z "$VALGRIND" ]; then
    export MALLOC_CHECK_=2
fi

server="$1"
username="$2"
password="$3"
domain="$4"
shift 4

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0
for bindoptions in connect sign seal sign,seal spnego spnego,sign spnego,seal validate padcheck bigendian bigendian,seal; do
 for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
     case $transport in
	 ncalrpc) tests=$ncalrpc_tests ;;
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    name="$t on $transport with $bindoptions"
    testit "$name" $VALGRIND bin/smbtorture $transport:"$server[$bindoptions]" -U"$username"%"$password" -W $domain $t "$*" || failed=`expr $failed + 1`
   done
 done
done

testok $0 $failed
