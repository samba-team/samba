#!/bin/sh
# Blackbox tests for samba-tool

SERVER=$1
SERVER_IP=$2
USERNAME=$3
PASSWORD=$4
DOMAIN=$5
DC=$6
PROV=$7
smbclient=$8
shift 8

failed=0

samba4bindir="$BINDIR"
samba_tool="$samba4bindir/samba-tool"

testit() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
		failed=`expr $failed + 1`
	fi
	return $status
}


testit "demote" $VALGRIND $samba_tool domain demote --server $DC -s $PROV/etc/smb.conf -W "$DOMAIN" -U"$USERNAME%$PASSWORD"

exit $failed
