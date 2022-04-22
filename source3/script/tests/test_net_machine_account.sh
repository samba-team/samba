#!/bin/sh
# Reproducer for https://bugzilla.samba.org/show_bug.cgi?id=14908

if [ $# -lt 2 ]; then
	echo "Usage: $0 NET CONFFILE SERVER_IP"
	exit 1
fi

NET="$1"
shift
CONFFILE="$1"
shift
SERVER_IP="$1"
shift

export UID_WRAPPER_ROOT=1

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

testit "net_ads_user" $VALGRIND $NET rpc user --configfile="$CONFFILE" -S "$SERVER_IP" -P || failed=$(expr $failed + 1)

testok $0 $failed
