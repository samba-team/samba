#!/bin/sh
# Test id mapping through idmap_rfc2307 module
if [ $# -lt 9 ]; then
	echo Usage: $0 DOMAIN USERNAME UID USERNAME2 UID2 GROUPNAME GID GROUPNAME2 GID2 LDAPPREFIX DC_SERVER DC_USERNAME DC_PASSWORD
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
LDAPPREFIX="$1"
DC_SERVER="$2"
DC_USERNAME="$3"
DC_PASSWORD="$4"

wbinfo="$VALGRIND $BINDIR/wbinfo"

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
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$USERNAME,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$USERNAME2,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$GROUPNAME,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$GROUPNAME2,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "$LDAPPREFIX"

# Add id mapping information to LDAP

cat > $PREFIX/tmpldb <<EOF
dn: $LDAPPREFIX
objectclass: organizationalUnit
EOF

testit "add ldap prefix" $VALGRIND $ldbadd -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD $PREFIX/tmpldb

cat > $PREFIX/tmpldb <<EOF
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

testit "add ldap user mapping record" $VALGRIND $ldbadd -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD $PREFIX/tmpldb

cat > $PREFIX/tmpldb <<EOF
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

testit "add second ldap user mapping record" $VALGRIND $ldbadd -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD $PREFIX/tmpldb

cat > $PREFIX/tmpldb <<EOF
dn: cn=$GROUPNAME,$LDAPPREFIX
objectClass: posixGroup
objectClass: groupOfNames
cn: $GROUPNAME
gidNumber: $GROUPGID
member: cn=$USERNAME,$LDAPPREFIX
EOF

testit "add ldap group mapping record" $VALGRIND $ldbadd -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD $PREFIX/tmpldb

cat > $PREFIX/tmpldb <<EOF
dn: cn=$GROUPNAME2,$LDAPPREFIX
objectClass: posixGroup
objectClass: groupOfNames
cn: $GROUPNAME2
gidNumber: $GROUPGID2
member: cn=$USERNAME,$LDAPPREFIX
EOF

testit "add second ldap group mapping record" $VALGRIND $ldbadd -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD $PREFIX/tmpldb

rm -f $PREFIX/tmpldbmodify

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

# Delete LDAP records
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$USERNAME,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$USERNAME2,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$GROUPNAME,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$GROUPNAME2,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "$LDAPPREFIX"

exit $failed
