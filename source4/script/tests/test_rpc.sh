#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="RPC-SPOOLSS RPC-SRVSVC RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND NET-API-RPCCONN-BIND NET-API-LISTSHARES NET-API-CREATEUSER NET-API-DELETEUSER"
ncalrpc_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND NET-API-LISTSHARES NET-API-CREATEUSER NET-API-DELETEUSER"
ncacn_ip_tcp_tests="RPC-SCHANNEL RPC-JOIN RPC-LSA RPC-ECHO RPC-DSSETUP RPC-ALTERCONTEXT RPC-MULTIBIND NET-API-LISTSHARES NET-API-CREATEUSER NET-API-DELETEUSER"
slow_ncacn_np_tests="RPC-SAMLOGON RPC-SAMR-USERS RPC-SAMR-PASSWORDS"
slow_ncalrpc_tests="RPC-SAMLOGON RPC-SAMR-USERS RPC-SAMR-PASSWORDS"
slow_ncacn_ip_tcp_tests="RPC-SAMLOGON RPC-SAMR-USERS RPC-SAMR-PASSWORDS"

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_rpc.sh SERVER USERNAME PASSWORD DOMAIN
EOF
exit 1;
fi

server="$1"
username="$2"
password="$3"
domain="$4"
shift 4

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0
for bindoptions in seal,validate,padcheck bigendian; do
 for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
     case $transport in
	 ncalrpc) tests=$ncalrpc_tests ;;
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    name="$t on $transport with $bindoptions"
    testit "$name" $VALGRIND bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" -U"$username"%"$password" -W $domain $t "$*" || failed=`expr $failed + 1`
   done
 done
done

for bindoptions in connect validate ; do
 for transport in ncalrpc; do
     case $transport in
	 ncalrpc) tests=$slow_ncalrpc_tests ;;
	 ncacn_np) tests=$slow_ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$slow_ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    name="$t on $transport with $bindoptions"
    testit "$name" $VALGRIND bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" -U"$username"%"$password" -W $domain $t "$*" || failed=`expr $failed + 1`
   done
 done
done

testok $0 $failed

