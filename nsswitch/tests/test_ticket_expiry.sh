#!/bin/sh
# Test winbind ad backend behaviour when the kerberos ticket expires

if [ $# -ne 1 ]; then
    echo Usage: $0 DOMAIN
    exit 1
fi

DOMAIN="$1"

wbinfo="$VALGRIND $BINDIR/wbinfo"
net="$VALGRIND $BINDIR/net"

failed=0

. `dirname $0`/../../testprogs/blackbox/subunit.sh

DOMAIN_SID=$($wbinfo -n "$DOMAIN/" | cut -f 1 -d " ")
if [ $? -ne 0 ] ; then
    echo "Could not find domain SID" | subunit_fail_test "test_idmap_ad"
    exit 1
fi
ADMINS_SID="$DOMAIN_SID-512"

# Previous tests might have put in a mapping
$net cache del IDMAP/SID2XID/"$ADMINS_SID"

# Trigger a winbind ad connection with a 5-second ticket lifetime,
# see the smb.conf for the ad_member_idmap_ad environment we're in
#
# We expect failure here because there are no mappings in AD. In this
# test we are only interested in the winbind LDAP connection as such,
# we don't really care whether idmap_ad works fine. This is done in
# different tests. And a negative lookup also triggers the LDAP
# connection.

testit_expect_failure "Deleting0 IDMAP/SID2XID/$ADMINS_SID" $net cache del IDMAP/SID2XID/"$ADMINS_SID" ||
    failed=$(expr $failed + 1)

testit_expect_failure "Expecting failure1, no mapping in AD" $wbinfo --sid-to-gid "$ADMINS_SID" ||
    failed=$(expr $failed + 1)

testit "Deleting1 IDMAP/SID2XID/$ADMINS_SID" $net cache del IDMAP/SID2XID/"$ADMINS_SID" ||
    failed=$(expr $failed + 1)

# allow our kerberos ticket to expire
testit "Sleeping for 6 seconds" sleep 6 || failed=$(expr $failed + 1)

# Try again, check how long it took to recover from ticket expiry
#
# On the LDAP connection two things happen: First we get an
# unsolicited exop response telling us the network session was
# abandoned, and secondly the LDAP server will kill the TCP
# connection. Our ldap server is configured to defer the TCP
# disconnect by 10 seconds. We need to make sure that winbind already
# reacts to the unsolicited exop reply, discarding the connection. The
# only way is to make sure the following wbinfo does not take too
# long.

# We need to do the test command in this funny way as on gitlab we're
# using the bash builtin

START=$(date +%s)
testit_expect_failure "Expecting failure2, no mapping in AD" $wbinfo --sid-to-gid "$ADMINS_SID" ||
    failed=$(expr $failed + 1)
END=$(date +%s)
DURATION=$(expr $END - $START)
testit "timeout DURATION[$DURATION] < 8" test "$DURATION" -le 8 ||
    failed=$(expr $failed + 1)

testit "Deleting2 IDMAP/SID2XID/$ADMINS_SID" $net cache del IDMAP/SID2XID/"$ADMINS_SID" ||
    failed=$(expr $failed + 1)

exit $failed
