#!/bin/sh
# Blackbox tests for net ads dns register etc.
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 6 ]; then
	cat <<EOF
Usage: test_net_ads_dns.sh SERVER DC_USERNAME DC_PASSWORD REALM USER PASS
EOF
	exit 1
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

samba_tool="$samba4bindir/samba-tool"
net_tool="$samba4bindir/net"
smbpasswd="$samba4bindir/smbpasswd"
texpect="$samba4bindir/texpect"

newuser="$samba_tool user create"
groupaddmem="$samba_tool group addmembers"

. $(dirname $0)/subunit.sh
. "$(dirname "${0}")/common_test_fns.inc"

ldbmodify=$(system_or_builddir_binary ldbmodify "${BINDIR}")
ldbsearch=$(system_or_builddir_binary ldbsearch "${BINDIR}")

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

IPADDRESS=10.1.4.111
IP6ADDRESS=fd00:1a1a::1:5ee:bad:c0de
IPADDRMAC=10.1.4.124
UNPRIVIP=10.1.4.130
ADMINNAME=testname.$$
MACHINENAME=membername.$$
UNPRIVNAME=unprivname.$$
UNPRIVUSER=unprivuser.$$
UNPRIVPASS=UnPrivPass1

# These tests check that privileged users can add DNS names and that
# unprivileged users cannot do so.
echo "Starting ..."

testit "admin user should be able to add a DNS entry $ADMINNAME.$REALM $IPADDRESS $IP6ADDRESS" \
	$VALGRIND $net_tool ads dns register $ADMINNAME.$REALM $IPADDRESS $IP6ADDRESS -U$DC_USERNAME%$DC_PASSWORD ||
	failed=$(expr $failed + 1)

testit_grep_count \
	"We should be able to see the new name $ADMINNAME.$REALM $IPADDRESS" \
	"$IPADDRESS" \
	1 \
	dig @$SERVER +short -t a $ADMINNAME.$REALM ||
	failed=$(expr $failed + 1)
testit_grep_count \
	"We should be able to see the new name $ADMINNAME.$REALM $IP6ADDRESS" \
	"$IP6ADDRESS" \
	1 \
	dig @$SERVER +short -t aaaa $ADMINNAME.$REALM ||
	failed=$(expr $failed + 1)

testit "We should be able to unregister the name $ADMINNAME.$REALM" \
	$VALGRIND $net_tool ads dns unregister $ADMINNAME.$REALM -U$DC_USERNAME%$DC_PASSWORD ||
	failed=$(expr $failed + 1)

testit_grep_count \
	"The name $ADMINNAME.$REALM $IPADDRESS should not be there any longer" \
	"$IPADDRESS" \
	0 \
	dig @$SERVER +short -t a $ADMINNAME.$REALM ||
	failed=$(expr $failed + 1)

testit_grep_count \
	"The name $ADMINNAME.$REALM $IP6ADDRESS should not be there any longer" \
	"$IP6ADDRESS" \
	0 \
	dig @$SERVER +short -t aaaa $ADMINNAME.$REALM ||
	failed=$(expr $failed + 1)

# prime the kpasswd server, see "git blame" for an explanation
$VALGRIND $net_tool user add $UNPRIVUSER $UNPRIVPASS -U$DC_USERNAME%$DC_PASSWORD
$VALGRIND $net_tool user delete $UNPRIVUSER -U$DC_USERNAME%$DC_PASSWORD

# This should be an expect_failure test ...
testit "Adding an unprivileged user" $VALGRIND $net_tool user add $UNPRIVUSER $UNPRIVPASS -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

BASEDN=$($VALGRIND $ldbsearch -U$DC_USERNAME%$DC_PASSWORD -H ldap://$SERVER.$REALM -b '' --scope=base defaultNamingContext | grep defaultNamingContext | sed -e 's!^defaultNamingContext: !!')

LDIF="dn: CN=$UNPRIVUSER,CN=users,${BASEDN}+changetype: modify+replace: userAccountControl+userAccountControl: 512"

echo $LDIF | tr '+' '\n' | $VALGRIND $ldbmodify -U$DC_USERNAME%$DC_PASSWORD -H ldap://$SERVER.$REALM -i
STATUS=$?

testit "We should have enabled the account" test $STATUS -eq 0 || failed=$(expr $failed + 1)

#Unprivileged users should be able to add new names
testit "Unprivileged users should be able to add new names" $net_tool ads dns register $UNPRIVNAME.$REALM $UNPRIVIP -U$UNPRIVUSER%$UNPRIVPASS || failed=$(expr $failed + 1)

# This should work as well
testit "machine account should be able to add a DNS entry net ads dns register $MACHINENAME.$REALM $IPADDRMAC -P" \
	$net_tool ads dns register $MACHINENAME.$REALM $IPADDRMAC -P ||
	failed=$(expr $failed + 1)

testit_grep_count \
	"We should be able to see the new name $MACHINENAME.$REALM" \
	"$IPADDRMAC" \
	1 \
	dig @$SERVER +short -t a $MACHINENAME.$REALM ||
	failed=$(expr $failed + 1)

#Unprivileged users should not be able to overwrite other's names
testit_expect_failure \
	"Unprivileged users should not be able to modify existing names" \
	$net_tool ads dns register $MACHINENAME.$REALM $UNPRIVIP -U$UNPRIVUSER%$UNPRIVPASS &&
	failed=$(expr $failed + 1)

testit "We should be able to unregister the name $UNPRIVNAME.$REALM $IPADDRESS" \
	$VALGRIND $net_tool ads dns unregister $UNPRIVNAME.$REALM -U$UNPRIVUSER%$UNPRIVPASS ||
	failed=$(expr $failed + 1)
testit "We should be able to unregister the name $MACHINENAME.$REALM $IPADDRESS" \
	$VALGRIND $net_tool ads dns unregister $MACHINENAME.$REALM -P ||
	failed=$(expr $failed + 1)

# Remove the unprivileged user, which is not required anymore
$VALGRIND $net_tool user delete $UNPRIVUSER -U$DC_USERNAME%$DC_PASSWORD

testit_grep_count \
	"The name $UNPRIVNAME.$REALM ($IPADDRESS) should not be there any longer" \
	"$IPADDRESS" \
	0 \
	dig @$SERVER +short -t a $UNPRIVNAME.$REALM ||
	failed=$(expr $failed + 1)
testit_grep_count \
	"The name $UNPRIVNAME.$REALM ($IP6ADDRESS) should not be there any longer" \
	"$IP6ADDRESS" \
	0 \
	dig @$SERVER +short -t aaaa $UNPRIVNAME.$REALM ||
	failed=$(expr $failed + 1)
testit_grep_count \
	"The name $MACHINENAME.$REALM ($IPADDRESS) should not be there any longer" \
	"$IPADDRESS" \
	0 \
	dig @$SERVER +short -t a $MACHINENAME.$REALM ||
	failed=$(expr $failed + 1)
testit_grep_count \
	"The name $MACHINENAME.$REALM ($IP6ADDRESS) should not be there any longer" \
	"$IP6ADDRESS" \
	0 \
	dig @$SERVER +short -t aaaa $MACHINENAME.$REALM ||
	failed=$(expr $failed + 1)

# Tests with --dns-ttl option
testit "net ads dns register with default TTL" \
	$net_tool ads dns register $MACHINENAME.$REALM $IPADDRMAC -P ||
	failed=$(expr $failed + 1)
TTL=$(dig @$SERVER.$REALM +noall +ttlid +answer -t A $MACHINENAME.$REALM |
	awk '{ print $2 }')
testit "Verify default TTL of 3600 seconds" \
	test "$TTL" = "3600" ||
	failed=$(expr $failed + 1)

testit "Update record with TTL of 60 seconds" \
	$net_tool ads dns register --dns-ttl 60 --force $MACHINENAME.$REALM $IPADDRMAC -P ||
	failed=$(expr $failed + 1)
TTL=$(dig @$SERVER.$REALM +noall +ttlid +answer -t A $MACHINENAME.$REALM |
	awk '{ print $2 }')
testit "Verify new TTL of 60 seconds" \
	test "$TTL" = "60" ||
	failed=$(expr $failed + 1)

testit "We should be able to unregister the name $MACHINENAME.$REALM $IPADDRESS" \
	$VALGRIND $net_tool ads dns unregister $MACHINENAME.$REALM -P ||
	failed=$(expr $failed + 1)

testit_grep_count \
	"The name $MACHINENAME.$REALM ($IPADDRESS) should not be there any longer" \
	"$IPADDRESS" \
	0 \
	dig @$SERVER.$REALM +short -t A $MACHINENAME.$REALM ||
	failed=$(expr $failed + 1)
testit_grep_count \
	"The name $MACHINENAME.$REALM ($IP6ADDRESS) should not be there any longer" \
	"$IP6ADDRESS" \
	0 \
	dig @$SERVER.$REALM +short -t AAAA $MACHINENAME.$REALM ||
	failed=$(expr $failed + 1)

testok $0 $failed
