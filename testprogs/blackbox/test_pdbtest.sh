#!/bin/sh
# Blackbox tests for pdbtest
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2012 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 2 ]; then
cat <<EOF
Usage: test_pdbtest.sh SERVER PREFIX USER SMBCLIENT SMB_CONF
EOF
exit 1;
fi

SERVER=$1
PREFIX=$2
USER=$3
smbclient=$4
SMB_CONF=$5
shift 5
failed=0

samba4bindir="$BINDIR"
pdbtest="$samba4bindir/pdbtest"
pdbedit="$samba4bindir/pdbedit"
net="$samba4bindir/net"
smbpasswd="$samba4bindir/smbpasswd"
texpect="$samba4bindir/texpect"

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

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

testit "pdbtest" $VALGRIND $BINDIR/pdbtest -u $USER $@ || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@01%

echo "set password with pdbedit"
cat > ./tmpsmbpasswdscript <<EOF
expect new password:
send ${NEWUSERPASS}\n
expect retype new password:
send ${NEWUSERPASS}\n
EOF

testit "create user with pdbedit" $texpect ./tmpsmbpasswdscript $VALGRIND $pdbedit -a $USER --account-desc="pdbedit-test-user" $@ || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

test_smbclient "Test login with user (ntlm)" 'ls' -k no -U$USER%$NEWUSERPASS $@ || failed=`expr $failed + 1`

testit "modify user"  $VALGRIND $pdbedit --modify $USER --drive="D:" $@ || failed=`expr $failed + 1`

test_smbclient "Test login with user (ntlm)" 'ls' -k no -U$USER%$NEWUSERPASS $@|| failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@02%

echo "set password with smbpasswd"
cat > ./tmpsmbpasswdscript <<EOF
expect New SMB password:
send ${NEWUSERPASS}\n
expect Retype new SMB password:
send ${NEWUSERPASS}\n
EOF

testit "set user password with smbpasswd" $texpect ./tmpsmbpasswdscript $smbpasswd -L $USER -c $SMB_CONF || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

test_smbclient "Test login with user (ntlm)" 'ls' -k no -U$USER%$NEWUSERPASS $@|| failed=`expr $failed + 1`

testit "modify user - disabled"  $VALGRIND $net sam set disabled $USER yes $@ || failed=`expr $failed + 1`

testit_expect_failure  "Test login with disabled suer" $VALGRIND $smbclient //$SERVER/tmp -c 'ls' -k no -U$USER@%$USERPASS && failed=`expr $failed + 1`

testit "modify user - enabled"  $VALGRIND $net sam set disabled $USER no $@ || failed=`expr $failed + 1`

test_smbclient "Test login with re-enabled user (ntlm)" 'ls' -k no -U$USER%$NEWUSERPASS || failed=`expr $failed + 1`

testit "modify user - must change password now"  $VALGRIND $net sam set pwdmustchangenow $USER yes $@ || failed=`expr $failed + 1`

testit_expect_failure  "Test login with expired password" $VALGRIND $smbclient //$SERVER/tmp -c 'ls' -k no -U$USER@%$USERPASS && failed=`expr $failed + 1`

testit "modify user - disable password expiry"  $VALGRIND $net sam set pwnoexp $USER yes $@ || failed=`expr $failed + 1`

test_smbclient "Test login with no expiry (ntlm)" 'ls' -k no -U$USER%$NEWUSERPASS || failed=`expr $failed + 1`

testit "del user"  $VALGRIND $pdbedit -x $USER $@ || failed=`expr $failed + 1`

rm ./tmpsmbpasswdscript

exit $failed
