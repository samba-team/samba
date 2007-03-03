#!/bin/sh

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests="NET-API-LOOKUP NET-API-LOOKUPHOST NET-API-LOOKUPPDC NET-API-RPCCONN-BIND NET-API-RPCCONN-SRV NET-API-RPCCONN-PDC NET-API-RPCCONN-DC NET-API-RPCCONN-DCINFO NET-API-LISTSHARES NET-API-CREATEUSER NET-API-DELETEUSER"
ncalrpc_tests="NET-API-RPCCONN-SRV NET-API-RPCCONN-DC NET-API-RPCCONN-DCINFO NET-API-LISTSHARES NET-API-CREATEUSER NET-API-DELETEUSER NET-USERINFO NET-USERADD NET-USERDEL NET-USERMOD NET-API-LOOKUPNAME NET-API-USERINFO NET-API-USERLIST NET-API-DOMOPENLSA NET-API-DOMCLOSELSA NET-API-DOMOPENSAMR NET-API-DOMCLOSESAMR"
ncacn_ip_tcp_tests="NET-API-LOOKUP NET-API-LOOKUPHOST NET-API-LOOKUPPDC NET-API-RPCCONN-SRV NET-API-RPCCONN-DC NET-API-RPCCONN-DCINFO NET-API-LISTSHARES NET-API-CREATEUSER NET-API-DELETEUSER NET-API-MODIFYUSER"

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net.sh SERVER USERNAME PASSWORD DOMAIN
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
for bindoptions in seal,padcheck $VALIDATE bigendian; do
 for transport in ncalrpc ncacn_np ncacn_ip_tcp; do
     case $transport in
	 ncalrpc) tests=$ncalrpc_tests ;;
	 ncacn_np) tests=$ncacn_np_tests ;;
	 ncacn_ip_tcp) tests=$ncacn_ip_tcp_tests ;;
     esac
   for t in $tests; do
    name="$t on $transport with $bindoptions"
    testit "$name" $VALGRIND bin/smbtorture $TORTURE_OPTIONS $transport:"$server[$bindoptions]" -U"$username"%"$password" -W $domain $t "$*"
   done
 done
done

testok $0 $failed
