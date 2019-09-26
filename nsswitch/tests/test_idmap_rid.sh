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

DOMAIN_SID=$($wbinfo -n "$DOMAIN/" | cut -f 1 -d " ")
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

#
# Test 3: ID_TYPE_BOTH mappings for group
#

GROUP="$DOMAIN/Domain Users"
GROUP_SID=$($wbinfo --name-to-sid="$GROUP" | sed -e 's/ .*//')

uid=$($wbinfo --sid-to-uid=$GROUP_SID)
ret=$?
testit "ID_TYPE_BOTH group map to uid succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
testit "ID_TYPE_BOTH group map to uid has result" test -n $uid ||\
	failed=$(expr $failed + 1)

gid=$($wbinfo --sid-to-gid=$GROUP_SID)
ret=$?
testit "ID_TYPE_BOTH group map to gid succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
testit "ID_TYPE_BOTH group map to gid has result" test -n $gid ||\
	failed=$(expr $failed + 1)

testit "ID_TYPE_BOTH group uid equals gid" test $uid -eq $gid ||\
	failed=$(expr $failed + 1)

group_pw="$DOMAIN/domain users:*:$uid:$gid::/home/$DOMAIN/domain users:/bin/false"

out=$(getent passwd "$GROUP")
ret=$?
testit "getpwnam for ID_TYPE_BOTH group succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

test "$out" = "$group_pw"
ret=$?
testit "getpwnam for ID_TYPE_BOTH group output" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

out=$(getent passwd $uid)
ret=$?
testit "getpwuid for ID_TYPE_BOTH group succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
test "$out" = "$group_pw"
ret=$?
testit "getpwuid for ID_TYPE_BOTH group output" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

group_gr="$DOMAIN/domain users:x:$gid:"

out=$(getent group "$GROUP")
ret=$?
testit "getgrnam for ID_TYPE_BOTH group succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
test "$out" = "$group_gr"
ret=$?
testit "getgrnam for ID_TYPE_BOTH group output" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

out=$(getent group "$gid")
ret=$?
testit "getgrgid for ID_TYPE_BOTH group succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
test "$out" = "$group_gr"
ret=$?
testit "getgrgid for ID_TYPE_BOTH group output" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

#
# Test 4: ID_TYPE_BOTH mappings for user
#

dom_users_gid=$gid

USER="$DOMAIN/Administrator"
USER_SID=$($wbinfo --name-to-sid="$USER" | sed -e 's/ .*//')

uid=$($wbinfo --sid-to-uid=$USER_SID)
ret=$?
testit "ID_TYPE_BOTH user map to uid succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
testit "ID_TYPE_BOTH user map to uid has result" test -n $uid ||\
	failed=$(expr $failed + 1)

gid=$($wbinfo --sid-to-gid=$USER_SID)
ret=$?
testit "ID_TYPE_BOTH user map to gid succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
testit "ID_TYPE_BOTH user map to gid has result" test -n $gid ||\
	failed=$(expr $failed + 1)

testit "ID_TYPE_BOTH user uid equals gid" test $uid -eq $gid ||\
	failed=$(expr $failed + 1)

user_pw="$DOMAIN/administrator:*:$uid:$dom_users_gid::/home/$DOMAIN/administrator:/bin/false"

out=$(getent passwd "$USER")
ret=$?
testit "getpwnam for ID_TYPE_BOTH user succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

test "$out" = "$user_pw"
ret=$?
testit "getpwnam for ID_TYPE_BOTH user output" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

out=$(getent passwd $uid)
ret=$?
testit "getpwuid for ID_TYPE_BOTH user succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
test "$out" = "$user_pw"
ret=$?
testit "getpwuid for ID_TYPE_BOTH user output" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

user_gr="$DOMAIN/administrator:x:$gid:$DOMAIN/administrator"

out=$(getent group "$USER")
ret=$?
testit "getgrnam for ID_TYPE_BOTH user succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
test "$out" = "$user_gr"
ret=$?
testit "getgrnam for ID_TYPE_BOTH user output" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

out=$(getent group "$gid")
ret=$?
testit "getgrgid for ID_TYPE_BOTH user succeeds" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)
test "$out" = "$user_gr"
ret=$?
testit "getgrgid for ID_TYPE_BOTH user output" test $ret -eq 0 ||\
	failed=$(expr $failed + 1)

exit $failed
