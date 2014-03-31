#!/bin/sh
# Test id mapping through idmap_rfc2307 module
if [ $# -lt 9 ]; then
	echo Usage: $0 DOMAIN USERNAME UID GROUPNAME GID LDAPPREFIX DC_SERVER DC_USERNAME DC_PASSWORD
	exit 1
fi

DOMAIN="$1"
USERNAME="$2"
USERUID="$3"
GROUPNAME="$4"
GROUPGID="$5"
LDAPPREFIX="$6"
DC_SERVER="$7"
DC_USERNAME="$8"
DC_PASSWORD="$9"

echo called with: $1 $2 $3 $4 $5 $6 $7 $8 $9

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
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$GROUPNAME,$LDAPPREFIX"
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
dn: cn=$GROUPNAME,$LDAPPREFIX
objectClass: posixGroup
objectClass: groupOfNames
cn: $GROUPNAME
gidNumber: $GROUPGID
member: cn=$USERNAME,$LDAPPREFIX
EOF

testit "add ldap group mapping record" $VALGRIND $ldbadd -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD $PREFIX/tmpldb

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

# Delete LDAP records
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$USERNAME,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "cn=$GROUPNAME,$LDAPPREFIX"
$VALGRIND $ldbdel -H ldap://$DC_SERVER -U$DOMAIN/$DC_USERNAME%$DC_PASSWORD "$LDAPPREFIX"

exit $failed
