#!/bin/sh

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_rpcclient_samlogon.sh USERNAME PASSWORD binding <rpcclient commands>
EOF
exit 1;
fi

USERNAME="$1"
PASSWORD="$2"
shift 2
ADDARGS="$*"

rpcclient_samlogon()
{
	$VALGRIND $BINDIR/rpcclient -U% -c "samlogon $USERNAME $PASSWORD;samlogon $USERNAME $PASSWORD" $@
}


incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
testit "rpcclient dsenumdomtrusts" $VALGRIND $BINDIR/rpcclient $ADDARGS -U% -c "dsenumdomtrusts" || failed=`expr $failed + 1`
testit "rpcclient getdcsitecoverage" $VALGRIND $BINDIR/rpcclient $ADDARGS -U% -c "getdcsitecoverage" || failed=`expr $failed + 1`
testit "rpcclient samlogon" rpcclient_samlogon $ADDARGS || failed=`expr $failed +1`

testok $0 $failed
