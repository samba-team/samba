#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

for I in "ncacn_np:\$SERVER" \
		 "ncacn_ip_tcp:\$SERVER" \
		 "ncacn_np:\$SERVER[rpcecho]"  \
		 "ncacn_np:\$SERVER[/pipe/rpcecho]" \
		 "ncacn_np:\$SERVER[/pipe/rpcecho,sign,seal]" \
		 "ncacn_np:\$SERVER[,sign]" \
		 "ncacn_ip_tcp:\$SERVER[,sign]" \
		 "ncalrpc:" \
		 "308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_np:\$SERVER" \
		 "308FB580-1EB2-11CA-923B-08002B1075A7@ncacn_ip_tcp:\$SERVER" 
do
	plantest "$I" dc bin/smbtorture $TORTURE_OPTIONS "$I" -U"\$USERNAME"%"\$PASSWORD" -W "\$DOMAIN" --option=torture:quick=yes RPC-ECHO "$*"
done
