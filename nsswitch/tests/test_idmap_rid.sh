#!/bin/sh
#
# Test id mapping with various SIDs and idmap_rid
#

if [ $# -lt 1 ]; then
	echo Usage: $0 DOMAIN RANGE_START
	exit 1
fi

DOMAIN="$1"
RANGE_START="$2"

wbinfo="$VALGRIND $BINDIR/wbinfo"
failed=0

. `dirname $0`/../../testprogs/blackbox/subunit.sh

DOMAIN_SID=$($wbinfo -n "@$DOMAIN" | cut -f 1 -d " ")
if [ $? -ne 0 ] ; then
    echo "Could not find domain SID" | subunit_fail_test "test_idmap_rid"
    exit 1
fi

# Find an unused uid and SID
RID=66666
MAX_RID=77777
while true ; do
    id $RID
    if [ $? -ne 0 ] ; then
	SID="$DOMAIN_SID-$RID"
	$wbinfo -s $SID
	if [ $? -ne 0 ] ; then
	    break
	fi
    fi
    RID=$(expr $RID + 1)
    if [ $RID -eq $MAX_RID ] ; then
	echo "Could not find free SID" | subunit_fail_test "test_idmap_rid"
	exit 1
    fi
done

#
# Test 1: Using non-existing SID to check backend returns a mapping
#

EXPECTED_ID=$(expr $RID + $RANGE_START)
out="$($wbinfo --sids-to-unix-ids=$SID)"
echo "wbinfo returned: \"$out\", expecting \"$SID -> uid/gid $EXPECTED_ID\""
test "$out" = "$SID -> uid/gid $EXPECTED_ID"
ret=$?
testit "Unknown RID from primary domain returns a mapping" test $ret -eq 0 || failed=$(expr $failed + 1)

#
# Test 2: Using bogus SID with bad domain part to check idmap backend does not generate a mapping
#

SID=S-1-5-21-1111-2222-3333-666
out="$($wbinfo --sids-to-unix-ids=$SID)"
echo "wbinfo returned: \"$out\", expecting \"$SID -> unmapped\""
test "$out" = "$SID -> unmapped"
ret=$?
testit "Bogus SID returns unmapped" test $ret -eq 0 || failed=$(expr $failed + 1)

exit $failed
