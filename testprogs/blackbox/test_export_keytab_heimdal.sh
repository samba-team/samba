#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

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

samba4bindir="$BINDIR"
samba_tool="$samba4bindir/samba-tool"
samba4ktutil="$BINDIR/samba4ktutil"
newuser="$samba_tool user create"

DNSDOMAIN=$(echo $REALM | tr '[:upper:]' '[:lower:]')
SERVER_FQDN="$SERVER.$DNSDOMAIN"

samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

test_keytab() {
	testname="$1"
	keytab="$2"
	principal="$3"
	expected_nkeys="$4"

	echo "test: $testname"

	NKEYS=$($VALGRIND $samba4ktutil $keytab | grep -i "$principal" | egrep -c "aes|arcfour")
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

USERPASS=testPaSS@01%
unc="//$SERVER/tmp"

testit "create user locally" $VALGRIND $PYTHON $newuser nettestuser $USERPASS $@ || failed=`expr $failed + 1`

testit "dump keytab from domain" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab $@ || failed=`expr $failed + 1`
test_keytab "read keytab from domain" "$PREFIX/tmpkeytab" "$SERVER\\\$" 3
testit "dump keytab from domain (2nd time)" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab $@ || failed=`expr $failed + 1`
test_keytab "read keytab from domain (2nd time)" "$PREFIX/tmpkeytab" "$SERVER\\\$" 3

testit "dump keytab from domain for cifs principal" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-server --principal=cifs/$SERVER_FQDN $@ || failed=`expr $failed + 1`
test_keytab "read keytab from domain for cifs principal" "$PREFIX/tmpkeytab-server" "cifs/$SERVER_FQDN" 3
testit "dump keytab from domain for cifs principal (2nd time)" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-server --principal=cifs/$SERVER_FQDN $@ || failed=`expr $failed + 1`
test_keytab "read keytab from domain for cifs principal (2nd time)" "$PREFIX/tmpkeytab-server" "cifs/$SERVER_FQDN" 3

testit "dump keytab from domain for user principal" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-2 --principal=nettestuser $@ || failed=`expr $failed + 1`
test_keytab "dump keytab from domain for user principal" "$PREFIX/tmpkeytab-2" "nettestuser@$REALM" 3
testit "dump keytab from domain for user principal (2nd time)" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-2 --principal=nettestuser@$REALM $@ || failed=`expr $failed + 1`
test_keytab "dump keytab from domain for user principal (2nd time)" "$PREFIX/tmpkeytab-2" "nettestuser@$REALM" 3

testit "dump keytab from domain for user principal with SPN as UPN" $VALGRIND $PYTHON $samba_tool domain exportkeytab $PREFIX/tmpkeytab-3 --principal=http/testupnspn.$DNSDOMAIN $@ || failed=`expr $failed + 1`
test_keytab "dump keytab from domain for user principal" "$PREFIX/tmpkeytab-3" "http/testupnspn.$DNSDOMAIN@$REALM" 3

KRB5CCNAME="$PREFIX/tmpuserccache"
export KRB5CCNAME

testit "kinit with keytab as user" $VALGRIND $samba4kinit --keytab=$PREFIX/tmpkeytab --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

testit "kinit with keytab as user (2)" $VALGRIND $samba4kinit --keytab=$PREFIX/tmpkeytab-2 --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache as user (2)" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpadminccache"
export KRB5CCNAME

testit "kinit with keytab as $USERNAME" $VALGRIND $samba4kinit --keytab=$PREFIX/tmpkeytab --request-pac $USERNAME@$REALM   || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpspnupnccache"
export KRB5CCNAME
testit "kinit with SPN from keytab" $VALGRIND $samba4kinit -k -t $PREFIX/tmpkeytab-3 http/testupnspn.$DNSDOMAIN || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpadminccache"
export KRB5CCNAME

testit "del user" $VALGRIND $PYTHON $samba_tool user delete nettestuser -k yes $@ || failed=`expr $failed + 1`

rm -f $PREFIX/tmpadminccache $PREFIX/tmpuserccache $PREFIX/tmpkeytab $PREFIX/tmpkeytab-2 $PREFIX/tmpkeytab-2 $PREFIX/tmpkeytab-server $PREFIX/tmpspnupnccache
exit $failed
