#!/bin/sh
#
# Basic testing of id mapping with idmap_ad
#

if [ $# -ne 3 ]; then
	echo Usage: $0 DOMAIN DC_SERVER DC_PASSWORD
	exit 1
fi

DOMAIN="$1"
DC_SERVER="$2"
DC_PASSWORD="$3"

wbinfo="$VALGRIND $BINDIR/wbinfo"
ldbmodify="$VALGRIND $BINDIR/ldbmodify"
ldbsearch="$VALGRIND $BINDIR/ldbsearch"

failed=0

. `dirname $0`/../../testprogs/blackbox/subunit.sh

DOMAIN_SID=$($wbinfo -n "@$DOMAIN" | cut -f 1 -d " ")
if [ $? -ne 0 ] ; then
    echo "Could not find domain SID" | subunit_fail_test "test_idmap_ad"
    exit 1
fi

BASE_DN=$($ldbsearch -H ldap://$DC_SERVER -b "" -s base defaultNamingContext | awk '/^defaultNamingContext/ {print $2}')
if [ $? -ne 0 ] ; then
    echo "Could not find base DB" | subunit_fail_test "test_idmap_ad"
    exit 1
fi

#
# Add POSIX ids to AD
#
cat <<EOF | $ldbmodify -H ldap://$DC_SERVER -U "$DOMAIN\Administrator%$DC_PASSWORD"
dn: CN=Administrator,CN=Users,$BASE_DN
changetype: modify
add: uidNumber
uidNumber: 2000000
EOF

cat <<EOF | $ldbmodify -H ldap://$DC_SERVER -U "$DOMAIN\Administrator%$DC_PASSWORD"
dn: CN=Domain Users,CN=Users,$BASE_DN
changetype: modify
add: gidNumber
gidNumber: 2000001
EOF

#
# Test 1: Test uid of Administrator, should be 2000000
#

out="$($wbinfo -S $DOMAIN_SID-500)"
echo "wbinfo returned: \"$out\", expecting \"2000000\""
test "$out" = "2000000"
ret=$?
testit "Test uid of Administrator is 2000000" test $ret -eq 0 || failed=$(expr $failed + 1)

#
# Test 2: Test gid of Domain Users, should be 2000001
#

out="$($wbinfo -Y $DOMAIN_SID-513)"
echo "wbinfo returned: \"$out\", expecting \"2000001\""
test "$out" = "2000001"
ret=$?
testit "Test uid of Domain Users is 2000001" test $ret -eq 0 || failed=$(expr $failed + 1)

#
# Test 3: Test get userinfo for Administrator works
#

out="$($wbinfo -i $DOMAIN/Administrator)"
echo "wbinfo returned: \"$out\", expecting \"$DOMAIN/administrator:*:2000000:2000001::/home/$DOMAIN/administrator:/bin/false\""
test "$out" = "$DOMAIN/administrator:*:2000000:2000001::/home/$DOMAIN/administrator:/bin/false"
ret=$?
testit "Test get userinfo for Administrator works" test $ret -eq 0 || failed=$(expr $failed + 1)

#
# Remove POSIX ids from AD
#
cat <<EOF | $ldbmodify -H ldap://$DC_SERVER -U "$DOMAIN\Administrator%$DC_PASSWORD"
dn: CN=Administrator,CN=Users,$BASE_DN
changetype: modify
delete: uidNumber
uidNumber: 2000000
EOF

cat <<EOF | $ldbmodify -H ldap://$DC_SERVER -U "$DOMAIN\Administrator%$DC_PASSWORD"
dn: CN=Domain Users,CN=Users,$BASE_DN
changetype: modify
delete: gidNumber
gidNumber: 2000001
EOF

exit $failed
