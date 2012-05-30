#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX ENCTYPE SMBCLINET
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
PREFIX=$6
ENCTYPE=$7
smbclient=$8
shift 8
failed=0

samba4bindir="$BINDIR"
samba4srcdir="$SRCDIR/source4"
samba4kinit="$samba4bindir/samba4kinit"
samba_tool="$samba4bindir/samba-tool"
ldbmodify="$samba4bindir/ldbmodify"
ldbsearch="$samba4bindir/ldbsearch"
rkpty="$samba4bindir/rkpty"
samba4kpasswd="$samba4bindir/samba4kpasswd"
enableaccount="$samba_tool user enable"
machineaccountccache="$samba4srcdir/scripting/bin/machineaccountccache"

. `dirname $0`/subunit.sh

test_smbclient() {
	name="$1"
	cmd="$2"
	shift
	shift
	echo "test: $name"
	$VALGRIND $smbclient $CONFIGURATION //$SERVER/tmp -c "$cmd" $@
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

enctype="-e $ENCTYPE"

KRB5CCNAME="$PREFIX/tmpccache"
export KRB5CCNAME

testit "kinit with pkinit (name specified)" $samba4kinit $enctype --request-pac --renewable --pk-user=FILE:$PREFIX/dc/private/tls/admincert.pem,$PREFIX/dc/private/tls/adminkey.pem $USERNAME@$REALM || failed=`expr $failed + 1`
testit "kinit with pkinit (enterprise name specified)" $samba4kinit $enctype --request-pac --renewable --pk-user=FILE:$PREFIX/dc/private/tls/admincert.pem,$PREFIX/dc/private/tls/adminkey.pem --enterprise $USERNAME@$REALM || failed=`expr $failed + 1`
testit "kinit with pkinit (enterprise name in cert)" $samba4kinit $enctype --request-pac --renewable --pk-user=FILE:$PREFIX/dc/private/tls/admincertupn.pem,$PREFIX/dc/private/tls/adminkey.pem --pk-enterprise || failed=`expr $failed + 1`
testit "kinit renew ticket" $samba4kinit --request-pac -R

test_smbclient "Test login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

rm -f $PREFIX/tmpccache
exit $failed
