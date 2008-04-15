#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2007 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
PREFIX=$6
shift 6
failed=0

samba4bindir=`dirname $0`/../../source/bin
smbclient=$samba4bindir/smbclient
samba4kinit=$samba4bindir/samba4kinit
net=$samba4bindir/net
enableaccount="$samba4bindir/smbpython `dirname $0`/../../source/setup/enableaccount"

testit() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}


test_smbclient() {
	name="$1"
	cmd="$2"
	shift
	shift
	echo "test: $name"
	$VALGRIND $smbclient $CONFIGURATION //$SERVER/tmp -c "$cmd" -W "$DOMAIN" -U"$USERNAME%$PASSWORD" $@
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

KRB5CCNAME="$PREFIX/tmpccache"
export KRB5CCNAME

echo $PASSWORD > ./tmppassfile
#testit "kinit with keytab" $samba4kinit --keytab=$PREFIX/dc/private/secrets.keytab $SERVER\$@$REALM   || failed=`expr $failed + 1`
testit "kinit with password" $samba4kinit --password-file=./tmppassfile --request-pac $USERNAME@$REALM   || failed=`expr $failed + 1`
testit "kinit with pkinit" $samba4kinit --request-pac --renewable --pk-user=FILE:$PREFIX/dc/private/tls/admincert.pem,$PREFIX/dc/private/tls/adminkey.pem $USERNAME@$REALM || failed=`expr $failed + 1`
testit "kinit renew ticket" $samba4kinit --request-pac -R

test_smbclient "Test login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

testit "domain join with kerberos ccache" $VALGRIND $net join $DOMAIN $CONFIGURATION  -W "$DOMAIN" -k yes $@ || failed=`expr $failed + 1`
testit "check time with kerberos ccache" $VALGRIND $net time $SERVER $CONFIGURATION  -W "$DOMAIN" -k yes $@ || failed=`expr $failed + 1`

testit "add user with kerberos ccache" $VALGRIND $net user add nettestuser $CONFIGURATION  -k yes $@ || failed=`expr $failed + 1`
USERPASS=testPass@12%
echo $USERPASS > ./tmpuserpassfile

testit "set user password with kerberos ccache" $VALGRIND $net password set $DOMAIN\\nettestuser $USERPASS $CONFIGURATION  -k yes $@ || failed=`expr $failed + 1`

testit "enable user with kerberos cache" $VALGRIND $enableaccount nettestuser -H ldap://$SERVER -k yes $@ || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpuserccache"
export KRB5CCNAME

testit "kinit with user password" $samba4bindir/samba4kinit --password-file=./tmpuserpassfile --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@34%
testit "change user password" $VALGRIND $net password change -W$DOMAIN -U$DOMAIN\\nettestuser%$USERPASS $CONFIGURATION  -k no $NEWUSERPASS $@ || failed=`expr $failed + 1`

echo $NEWUSERPASS > ./tmpuserpassfile
testit "kinit with user password" $samba4bindir/samba4kinit --password-file=./tmpuserpassfile --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpccache"
export KRB5CCNAME

testit "del user with kerberos ccache" $VALGRIND $net user delete nettestuser $CONFIGURATION -k yes $@ || failed=`expr $failed + 1`

rm -f tmpccfile tmppassfile tmpuserpassfile tmpuserccache
exit $failed
