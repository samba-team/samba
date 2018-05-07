#!/bin/sh
# Test id mapping with unknown SID and non-allocating idmap backend
if [ $# -lt 1 ]; then
	echo Usage: $0 DOMAIN
	exit 1
fi

DOMAIN="$1"

wbinfo="$VALGRIND $BINDIR/wbinfo"

failed=0

. `dirname $0`/../../testprogs/blackbox/subunit.sh

testit "wbinfo returns domain SID" $wbinfo -n "$DOMAIN/" || exit 1
DOMAIN_SID=$($wbinfo -n "$DOMAIN/" | cut -f 1 -d " ")
echo "Domain $DOMAIN has SID $DOMAIN_SID"

# Find an unused uid and SID
RID=66666
while true ; do
    id $RID
    if [ $? -ne 0 ] ; then
	$wbinfo -s $DOMAIN_SID-$RID
	if [ $? -ne 0 ] ; then
	    break
	fi
    fi
    RID=$(expr $RID + 1)
done

echo "Using non-existing SID $DOMAIN_SID-$RID to check no id allocation is done by the backend"

out="$($wbinfo --sids-to-unix-ids=$DOMAIN_SID-$RID)"
echo "wbinfo returned: $out"
test "$out" = "$DOMAIN_SID-$RID -> unmapped"
ret=$?
testit "wbinfo SID to xid returns unmapped for unknown SID" test $ret -eq 0 || failed=$(expr $failed + 1)

exit $failed
