#!/bin/sh
#
# Blackbox tests for an exported keytab with kinit
#
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>
# Copyright (C) 2016      Andreas Schneider <asn@cryptomilk.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_extract_keytab.sh SERVER USERNAME REALM DOMAIN PREFIX SMBCLIENT
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
REALM=$3
DOMAIN=$4
PREFIX=$5
smbclient=$6
shift 6
failed=0

samba_bindir="$BINDIR"
samba_tool="$samba_bindir/samba-tool"
samba_newuser="$samba_tool user create"
samba_texpect="$samba_bindir/texpect"
samba_ktutil="$BINDIR/samba4ktutil"

samba_kinit=kinit
samba_kdestroy=kdestroy

SERVER_FQDN="$SERVER.$(echo $REALM | tr '[:upper:]' '[:lower:]')"

source `dirname $0`/subunit.sh

test_smbclient() {
	name="$1"
	cmd="$2"
	shift
	shift
	echo "test: $name"
	$VALGRIND $smbclient //$SERVER/tmp -c "$cmd" $@
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

test_keytab() {
	testname="$1"
	keytab="$2"
	principal="$3"
	expected_nkeys="$4"

	echo "test: $testname"

	NKEYS=$($VALGRIND $samba_ktutil $keytab | grep -i "$principal" | egrep -c "DES|AES|ArcFour")
	status=$?
	if [ x$status != x0 ]; then
		echo "failure: $testname"
		return $status
	fi

	if [ x$NKEYS != x$expected_nkeys ] ; then
		echo "failure: $testname"
		return 1
	fi
	echo "success: $testname"
	return 0
}

TEST_USER=nettestuser
TEST_PASSWORD=testPaSS@01%

testit "create local user $TEST_USER" $VALGRIND $PYTHON $samba_newuser $TEST_USER $TEST_PASSWORD $@ || failed=`expr $failed + 1`

testit "dump keytab from domain" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-all $@ || failed=`expr $failed + 1`
test_keytab "read keytab from domain" "$PREFIX/tmpkeytab-all" "$SERVER\\\$" 5

testit "dump keytab from domain (2nd time)" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-all $@ || failed=`expr $failed + 1`
test_keytab "read keytab from domain (2nd time)" "$PREFIX/tmpkeytab-all" "$SERVER\\\$" 5

testit "dump keytab from domain for cifs service principal" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-server --principal=cifs/$SERVER_FQDN $@ || failed=`expr $failed + 1`
test_keytab "read keytab from domain for cifs service principal" "$PREFIX/tmpkeytab-server" "cifs/$SERVER_FQDN" 5
testit "dump keytab from domain for cifs service principal (2nd time)" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-server --principal=cifs/$SERVER_FQDN $@ || failed=`expr $failed + 1`
test_keytab "read keytab from domain for cifs service principal (2nd time)" "$PREFIX/tmpkeytab-server" "cifs/$SERVER_FQDN" 5

testit "dump keytab from domain for user principal" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-user-princ --principal=$TEST_USER $@ || failed=`expr $failed + 1`
test_keytab "dump keytab from domain for user principal" "$PREFIX/tmpkeytab-user-princ" "$TEST_USER@$REALM" 5
testit "dump keytab from domain for user principal (2nd time)" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-user-princ --principal=$TEST_USER@$REALM $@ || failed=`expr $failed + 1`
test_keytab "dump keytab from domain for user principal (2nd time)" "$PREFIX/tmpkeytab-user-princ" "$TEST_USER@$REALM" 5

KRB5CCNAME="$PREFIX/tmpuserccache"
export KRB5CCNAME

testit "kinit with keytab as user" $VALGRIND $samba_kinit -k -t $PREFIX/tmpkeytab-all $TEST_USER@$REALM || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`
$samba_kdestroy

testit "kinit with keytab as user (one princ)" $VALGRIND $samba_kinit -k -t $PREFIX/tmpkeytab-user-princ $TEST_USER@$REALM || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache (one princ)" 'ls' -k yes || failed=`expr $failed + 1`
$samba_kdestroy

KRB5CCNAME="$PREFIX/tmpadminccache"
export KRB5CCNAME

testit "kinit with keytab as $USERNAME" $VALGRIND $samba_kinit -k -t $PREFIX/tmpkeytab-all $USERNAME@$REALM || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpserverccache"
export KRB5CCNAME
echo "$samba_kinit -k -t $PREFIX/tmpkeytab-server cifs/$SERVER_FQDN"
testit "kinit with SPN from keytab" $VALGRIND $samba_kinit -k -t $PREFIX/tmpkeytab-server cifs/$SERVER_FQDN || failed=`expr $failed + 1`

# cleanup
testit "delete user $TEST_USER" $VALGRIND $PYTHON $samba_tool user delete nettestuser -k yes $@ || failed=`expr $failed + 1`

$samba_kdestroy
rm -f $PREFIX/tmpadminccache $PREFIX/tmpuserccache $PREFIX/tmpkeytab $PREFIX/tmpkeytab-2 $PREFIX/tmpkeytab-server

exit $failed
