#!/bin/sh
# Blackbox tests for net ads dns register etc.
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_net_ads_dns.sh SERVER DC_USERNAME DC_PASSWORD REALM USER PASS
EOF
exit 1;
fi

SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3
REALM=$4
USERNAME=$5
PASSWORD=$6
shift 6
failed=0

samba4bindir="$BINDIR"
samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi

samba_tool="$samba4bindir/samba-tool"
net_tool="$samba4bindir/net"
smbpasswd="$samba4bindir/smbpasswd"
texpect="$samba4bindir/texpect"
samba4kpasswd=kpasswd
if test -x $BINDIR/samba4kpasswd; then
	samba4kpasswd=$BINDIR/samba4kpasswd
fi
ldbsearch="$samba4bindir/ldbsearch"
ldbmodify="$samba4bindir/ldbmodify"

newuser="$samba_tool user create"
groupaddmem="$samba_tool group addmembers"

. `dirname $0`/subunit.sh

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

IPADDRESS=10.1.4.111
IPADDRMAC=10.1.4.124
UNPRIVIP=10.1.4.130
NAME=testname
UNPRIVNAME=unprivname
UNPRIVUSER=unprivuser
UNPRIVPASS=UnPrivPass1

# These tests check that privileged users can add DNS names and that
# unprivileged users cannot do so.
echo "Starting ..."

testit "admin user should be able to add a DNS entry $NAME.$REALM $IPADDRESS" $VALGRIND $net_tool ads dns register $NAME.$REALM $IPADDRESS -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

# The complicated pipeline is to ensure that we remove exclamation points
# and spaces from the output. Thew will screw up the comparison syntax.
testit "We should be able to see the new name $NAME.$REALM" [ X"`$VALGRIND $net_tool ads dns gethostbyname $SERVER $NAME.$REALM -U$DC_USERNAME%$DC_PASSWORD | tr \! N | tr " " B`" = X"$IPADDRESS" ] || failed=`expr $failed + 1`

testit "We should be able to unregister the name $NAME.$REALM $IPADDRESS" $VALGRIND $net_tool ads dns unregister $NAME.$REALM -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

# The complicated pipeline is to ensure that we remove exclamation points
# and spaces from the output. Thew will screw up the comparison syntax.
testit "The name $NAME.$REALM should not be there any longer" test X"`$net_tool ads dns gethostbyname $SERVER $NAME.$REALM -U$DC_USERNAME%$DC_PASSWORD | tr " " B | tr \! N`" != X"$IPADDRESS" || failed=`expr $failed + 1`

# This should be an expect_failure test ...
testit "Adding an unprivileged user" $VALGRIND $net_tool user add $UNPRIVUSER $UNPRIVPASS -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

BASEDN=$($VALGRIND $ldbsearch -U$DC_USERNAME%$DC_PASSWORD -H ldap://$SERVER.$REALM -b '' -s base defaultNamingContext | grep defaultNamingContext | sed -e 's!^defaultNamingContext: !!')

LDIF="dn: CN=$UNPRIVUSER,CN=users,${BASEDN}+changetype: modify+replace: userAccountControl+userAccountControl: 512"

echo $LDIF | tr '+' '\n' | $VALGRIND $ldbmodify -U$DC_USERNAME%$DC_PASSWORD -H ldap://$SERVER.$REALM -i
STATUS=$?

testit "We should have enabled the account" test $STATUS -eq 0 || failed=`expr $failed + 1`

#Unprivileged users should be able to add new names
testit "Unprivileged users should be able to add new names" $net_tool ads dns register $UNPRIVNAME.$REALM $UNPRIVIP -U$UNPRIVUSER%$UNPRIVPASS || failed=`expr $failed + 1`

# This should work as well
testit "machine account should be able to add a DNS entry net ads dns register membername.$REALM $IPADDRMAC -P " $net_tool ads dns register membername.$REALM $IPADDRMAC -P || failed=`expr $failed + 1`

# The complicated pipeline is to ensure that we remove exclamation points
# and spaces from the output. Thew will screw up the comparison syntax.
testit "We should be able to see the new name membername.$REALM using -P" [ X"`$VALGRIND $net_tool ads dns gethostbyname $SERVER membername.$REALM -P | tr \! N | tr " " B`" = X"$IPADDRMAC" ] || failed=`expr $failed + 1`

#Unprivileged users should not be able to overwrite other's names
testit_expect_failure "Unprivileged users should not be able modify existing names" $net_tool ads dns register membername.$REALM $UNPRIVIP -U$UNPRIVUSER%$UNPRIVPASS || failed=`expr $failed + 1`

testit "We should be able to unregister the name $NAME.$REALM $IPADDRESS" $VALGRIND $net_tool ads dns unregister $NAME.$REALM -P || failed=`expr $failed + 1`

# The complicated pipeline is to ensure that we remove exclamation points
# and spaces from the output. Thew will screw up the comparison syntax.
testit "The name $NAME.$REALM should not be there any longer" test X"`$net_tool ads dns gethostbyname $SERVER $NAME.$REALM -P | tr " " B | tr \! N`" != X"$IPADDRESS" || failed=`expr $failed + 1`

exit $failed
