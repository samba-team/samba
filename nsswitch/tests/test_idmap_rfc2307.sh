#!/bin/sh
# Test id mapping through idmap_rfc2307 module
if [ $# -lt 15 ]; then
    echo Usage: $0 DOMAIN USERNAME UID USERNAME2 UID2 \
	 GROUPNAME GID GROUPNAME2 GID2 GID_START NUMGROUPS \
	 LDAPPREFIX DC_SERVER DC_USERNAME DC_PASSWORD
	exit 1
fi

DOMAIN="$1"
USERNAME="$2"
USERUID="$3"
USERNAME2="$4"
USERUID2="$5"
GROUPNAME="$6"
GROUPGID="$7"
GROUPNAME2="$8"
GROUPGID2="$9"
shift 9
GID_START="$1"
NUMGROUPS="$2"
LDAPPREFIX="$3"
DC_SERVER="$4"
DC_USERNAME="$5"
DC_PASSWORD="$6"

wbinfo="$VALGRIND $BINDIR/wbinfo"
net="$VALGRIND $BINDIR/net"

ldbsearch="ldbsearch"
if [ -x "$BINDIR/ldbsearch" ]; then
	ldbsearch="$BINDIR/ldbsearch"
fi

ldbadd="ldbadd"
if [ -x "$BINDIR/ldbadd" ]; then
	ldbadd="$BINDIR/ldbadd"
fi

ldbdel="ldbdel"
if [ -x "$BINDIR/ldbdel" ]; then
	ldbdel="$BINDIR/ldbdel"
fi

failed=0

. `dirname $0`/../../testprogs/blackbox/subunit.sh

# Delete LDAP records
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "$LDAPPREFIX" --controls="tree_delete:1"

# Add id mapping information to LDAP

testit "add ldap prefix" $VALGRIND $ldbadd -H ldap://$DC_SERVER \
        -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD <<EOF
dn: $LDAPPREFIX
objectclass: organizationalUnit
EOF

testit "add ldap user mapping record" $VALGRIND $ldbadd -H ldap://$DC_SERVER \
        -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD <<EOF
dn: cn=$USERNAME,$LDAPPREFIX
objectClass: organizationalPerson
objectClass: posixAccount
ou: People
cn: $USERNAME
uid: $USERNAME
uidNumber: $USERUID
gidNumber: 1
homeDirectory: /home/admin
EOF

testit "add second ldap user mapping record" $VALGRIND $ldbadd \
       -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD <<EOF
dn: cn=$USERNAME2,$LDAPPREFIX
objectClass: organizationalPerson
objectClass: posixAccount
ou: People
cn: $USERNAME2
uid: $USERNAME2
uidNumber: $USERUID2
gidNumber: 2
homeDirectory: /home/admin
EOF

testit "add ldap group mapping record" $VALGRIND $ldbadd \
       -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD <<EOF
dn: cn=$GROUPNAME,$LDAPPREFIX
objectClass: posixGroup
objectClass: groupOfNames
cn: $GROUPNAME
gidNumber: $GROUPGID
member: cn=$USERNAME,$LDAPPREFIX
EOF

testit "add second ldap group mapping record" $VALGRIND $ldbadd \
       -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD <<EOF
dn: cn=$GROUPNAME2,$LDAPPREFIX
objectClass: posixGroup
objectClass: groupOfNames
cn: $GROUPNAME2
gidNumber: $GROUPGID2
member: cn=$USERNAME,$LDAPPREFIX
EOF

testit "wbinfo --name-to-sid" $wbinfo --name-to-sid "$DOMAIN/$USERNAME" || failed=$(expr $failed + 1)
user_sid=$($wbinfo -n "$DOMAIN/$USERNAME" | cut -d " " -f1)
echo "$DOMAIN/$USERNAME resolved to $user_sid"

testit "wbinfo --sid-to-uid=$user_sid" $wbinfo --sid-to-uid=$user_sid || failed=$(expr $failed + 1)
user_uid=$($wbinfo --sid-to-uid=$user_sid | cut -d " " -f1)
echo "$DOMAIN/$USERNAME resolved to $user_uid"

testit "test $user_uid -eq $USERUID" test $user_uid -eq $USERUID || failed=$(expr $failed + 1)

# Not sure how to get group names with spaces to resolve through testit
#testit "wbinfo --name-to-sid" $wbinfo --name-to-sid="$DOMAIN/$GROUPNAME" || failed=$(expr $failed + 1)
group_sid=$($wbinfo --name-to-sid="$DOMAIN/$GROUPNAME" | cut -d " " -f1)
echo "$DOMAIN/$GROUPNAME resolved to $group_sid"

testit "wbinfo --sid-to-gid=$group_sid" $wbinfo --sid-to-gid=$group_sid || failed=$(expr $failed + 1)
group_gid=$($wbinfo --sid-to-gid=$group_sid | cut -d " " -f1)
echo "$DOMAIN/$GROUPNAME resolved to $group_gid"

testit "test $group_gid -eq $GROUPGID" test $group_gid -eq $GROUPGID || failed=$(expr $failed + 1)

# Use different user and group for reverse lookup to not read from cache

testit "$wbinfo --uid-to-sid=$USERUID2" $wbinfo --uid-to-sid=$USERUID2 || failed=$(expr $failed + 1)
user_sid2=$($wbinfo --uid-to-sid=$USERUID2 | cut -d " " -f1)
echo "UID $USERUID2 resolved to SID $user_sid2"

testit "$wbinfo --sid-to-name=$user_sid2" $wbinfo --sid-to-name=$user_sid2 || failed=$(expr $failed + 1)
user_name2=$($wbinfo --sid-to-name=$user_sid2 | cut -d " " -f1)
echo "SID $user_sid2 resolved to $user_name2"

testit "test $user_name2 = $DOMAIN/$USERNAME2" test "$(echo $user_name2 | tr A-Z a-z)" = "$(echo $DOMAIN/$USERNAME2 | tr A-Z a-z)" || failed=$(expr $failed + 1)

testit "$wbinfo --gid-to-sid=$GROUPGID2" $wbinfo --gid-to-sid=$GROUPGID2 || failed=$(expr $failed + 1)
group_sid2=$($wbinfo --gid-to-sid=$GROUPGID2 | cut -d " " -f1)
echo "GID $GROUPGID2 resolved to SID $group_sid2"

testit "$wbinfo --sid-to-name=$group_sid2" $wbinfo --sid-to-name=$group_sid2 || failed=$(expr $failed + 1)
group_name2=$($wbinfo --sid-to-name=$group_sid2 | cut -d " " -f1)
echo "SID $group_sid2 resolved to $group_name2"

testit "test $group_name2 = $DOMAIN/$GROUPNAME2" test "$(echo $group_name2 | tr A-Z a-z)" = "$(echo $DOMAIN/$GROUPNAME2 | tr A-Z a-z)" || failed=$(expr $failed + 1)

i=0
while [ ${i} -lt ${NUMGROUPS} ] ; do
    GRP=$(printf "test_rfc2307_group_%3.3d" "$i")
    GRP_GID=$(expr "$GID_START" + "$i")
    testit "Add group $GRP" $net rpc group add "$GRP" -S "$DC_SERVER" \
	   -U"${DOMAIN}\\${DC_USERNAME}"%"${DC_PASSWORD}" ||
	failed=$(expr $failed + 1)
    testit "Add groupmem $GRP $USERNAME" \
	   $net rpc group addmem "$GRP" "$USERNAME" \
	   -S "$DC_SERVER" \
	   -U"${DOMAIN}\\${DC_USERNAME}"%"${DC_PASSWORD}" ||
	failed=$(expr $failed + 1)
    testit "Add group object for $GRP $GRP_GID" \
	   $VALGRIND $ldbadd \
       -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD <<EOF
dn: cn=$GRP,$LDAPPREFIX
objectClass: posixGroup
objectClass: groupOfNames
cn: $GRP
gidNumber: $GRP_GID
member: cn=$USERNAME,$LDAPPREFIX
EOF
    i=$(expr "$i" + 1)
done

# Test whether wbinfo --xids-to-sids finds everything

GIDS=""
i=0
while [ ${i} -lt ${NUMGROUPS} ] ; do
    GIDS="$GIDS g$(expr ${i} + ${GID_START})"
    i=$(expr "$i" + 1)
done
NUM_VALID_SIDS=$($wbinfo --unix-ids-to-sids="$GIDS" | grep -v ^"NOT MAPPED" | wc -l)

testit "Count number of valid sids found" \
       test ${NUM_VALID_SIDS} = ${NUMGROUPS} ||
       failed=$(expr $failed + 1)

# Prime the cache so we test idmap, not the harder problem of
# consistent group memberships for users without a login.

testit "Authenticate the user to prime the netlogon cache" \
       $wbinfo -a $DOMAIN/$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

# Test whether wbinfo -r shows all groups

EXPECTED_USERGROUPS="1000000/1000001/2000002/"
i=0
while [ ${i} -lt ${NUMGROUPS} ] ; do
    EXPECTED_USERGROUPS="$EXPECTED_USERGROUPS$(expr ${i} + ${GID_START})/"
    i=$(expr "$i" + 1)
done

USERGROUPS=$($wbinfo -r $DOMAIN/$USERNAME | sort -n | tr '\n' '/')

testit "Testing for expected group memberships" \
       test "$USERGROUPS" = "$EXPECTED_USERGROUPS" ||
       failed=$(expr $failed + 1)

i=0
while [ ${i} -lt ${NUMGROUPS} ] ; do
    GRP=$(printf "test_rfc2307_group_%3.3d" ${i})
    testit "Del group $GRP" $net rpc group delete "$GRP" -S "$DC_SERVER" \
	   -U"${DOMAIN}\\${DC_USERNAME}"%"${DC_PASSWORD}" ||
	failed=$(expr $failed + 1)
    i=$(expr "$i" + 1)
done

# Delete LDAP records
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "$LDAPPREFIX" --controls="tree_delete:1"

exit $failed
