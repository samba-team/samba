#!/bin/sh

if [ $# -lt 2 ] ; then
cat <<EOF
Usage: test_libwbclient_threads.sh DOMAIN USERNAME
EOF
exit 1;
fi

DOMAIN="$1"
USERNAME="$2"
shift 2

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "libwbclient-threads" "$BINDIR/stress-nss-libwbclient" "$DOMAIN/$USERNAME"
