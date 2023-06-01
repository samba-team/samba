#!/bin/sh
# This tests listing directories using the SMBSearch call family

if [ $# -lt 2 ]; then
    cat <<EOF
Usage: $0 TIMELIMIT SMBCLIENT
EOF
    exit 1
fi

TIMELIMIT="$1"
shift
SMBCLIENT="$VALGRIND $1"
shift

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

# Make sure we don't loop 100% CPU. A normal dir listing should return
# in less than 3 seconds. At the point of this commit smbclient -c dir
# | wc returns 43 lines, so checking for 100 lines should be well
# enough.

count=$($TIMELIMIT 3 $SMBCLIENT //"$SERVER_IP"/tmpguest -m LANMAN1 -U% \
		   -c dir | wc -l)

testit "listing shares with LANMAN1" test ${count} -le 100 ||
    failed=$((failed + 1))
