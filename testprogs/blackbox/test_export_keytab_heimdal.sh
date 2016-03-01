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
newuser="$samba_tool user create"

samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi

. `dirname $0`/subunit.sh

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

USERPASS=testPaSS@01%

testit "create user locally" $VALGRIND $newuser nettestuser $USERPASS $@ || failed=`expr $failed + 1`

testit "dump keytab from domain" $VALGRIND $samba_tool domain exportkeytab $PREFIX/tmpkeytab $@ || failed=`expr $failed + 1`
testit "dump keytab from domain (2nd time)" $VALGRIND $samba_tool domain exportkeytab $PREFIX/tmpkeytab $@ || failed=`expr $failed + 1`

testit "dump keytab from domain for cifs principal" $VALGRIND $samba_tool domain exportkeytab $PREFIX/tmpkeytab-server --principal=cifs/$SERVER $@ || failed=`expr $failed + 1`
testit "dump keytab from domain for cifs principal (2nd time)" $VALGRIND $samba_tool domain exportkeytab $PREFIX/tmpkeytab-server --principal=cifs/$SERVER $@ || failed=`expr $failed + 1`

testit "dump keytab from domain for user principal" $VALGRIND $samba_tool domain exportkeytab $PREFIX/tmpkeytab-2 --principal=nettestuser $@ || failed=`expr $failed + 1`
testit "dump keytab from domain for user principal (2nd time)" $VALGRIND $samba_tool domain exportkeytab $PREFIX/tmpkeytab-2 --principal=nettestuser@$REALM $@ || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpuserccache"
export KRB5CCNAME

testit "kinit with keytab as user" $VALGRIND $samba4kinit --keytab=$PREFIX/tmpkeytab --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

testit "kinit with keytab as user (2)" $VALGRIND $samba4kinit --keytab=$PREFIX/tmpkeytab-2 --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache as user (2)" 'ls' -k yes || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpadminccache"
export KRB5CCNAME

testit "kinit with keytab as $USERNAME" $VALGRIND $samba4kinit --keytab=$PREFIX/tmpkeytab --request-pac $USERNAME@$REALM   || failed=`expr $failed + 1`

testit "del user" $VALGRIND $samba_tool user delete nettestuser -k yes $@ || failed=`expr $failed + 1`

rm -f $PREFIX/tmpadminccache $PREFIX/tmpuserccache $PREFIX/tmpkeytab $PREFIX/tmpkeytab-2 $PREFIX/tmpkeytab-server
exit $failed
