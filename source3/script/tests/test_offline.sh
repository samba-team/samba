#!/bin/sh
#
# Blackbox test for the offline VFS module.
#
if [ $# -lt 7 ]; then
cat <<EOF
Usage: test_offline SERVER SERVER_IP DOMAIN USERNAME PASSWORD WORKDIR SMBCLIENT
EOF
exit 1;
fi

SERVER=${1}
SERVER_IP=${2}
DOMAIN=${3}
USERNAME=${4}
PASSWORD=${5}
WORKDIR=${6}
SMBCLIENT=${7}
shift 7
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

touch $WORKDIR/foo

failed=0

attribs=`$SMBCLIENT -U$USERNAME%$PASSWORD "//$SERVER/offline" -I $SERVER_IP -c "allinfo foo" | sed -n 's/^attributes:.*(\([^)]*\)).*/\1/p'`
testit "file has offline attribute" test "x$attribs" = "x1000"  || failed=`expr $failed + 1`

exit $failed
