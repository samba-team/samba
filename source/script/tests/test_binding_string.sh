#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_binding_string.sh SERVER USERNAME PASSWORD DOMAIN
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

failed=0;
for I in "ncacn_np:$server" \
		 "ncacn_ip_tcp:$server" \
		 "ncacn_np:$server[rpcecho]"  \
		 "ncacn_np:$server[/pipe/rpcecho]" \
		 "ncacn_np:$server[/pipe/rpcecho,sign,seal]" \
		 "ncacn_np:$server[,sign]" \
		 "ncacn_ip_tcp:$server[,sign]" \
		 "ncalrpc:" \
		 "308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:$server" \
		 "308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:$server" 
do
	testit "$I" bin/smbtorture $TORTURE_OPTIONS "$I" -U"$username"%"$password" -W $domain --option=torture:quick=yes RPC-ECHO "$*"
done

testok $0 $failed
