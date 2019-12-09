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
unc="//$SERVER/tmp"

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

test_smbpasswd()
{
	user=$1
	newpass=$2

	echo "set password with smbpasswd"
	tmpfile=$PREFIX/smbpasswd_change_password_script
	cat > $tmpfile <<EOF
expect New SMB password:
send ${newpass}\n
expect Retype new SMB password:
send ${newpass}\n
EOF

	cmd='UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $texpect $tmpfile $smbpasswd -L $user -c $SMB_CONF'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "Failed to change user password $user"
		return 1
	fi
}

testit "pdbtest" $VALGRIND $BINDIR/pdbtest -u $USER $@ || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@01%

echo "set password with pdbedit"
cat > ./tmpsmbpasswdscript <<EOF
expect new password:
send ${NEWUSERPASS}\n
expect retype new password:
send ${NEWUSERPASS}\n
EOF

testit "create user with pdbedit" $texpect ./tmpsmbpasswdscript $VALGRIND $pdbedit -s $SMB_CONF -a $USER --account-desc="pdbedit-test-user" $@ || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

test_smbclient "Test login with user (ntlm)" 'ls' "$unc"  -U$USER%$NEWUSERPASS $@ || failed=`expr $failed + 1`

testit "modify user"  $VALGRIND $pdbedit -s $SMB_CONF --modify $USER --drive="D:" $@ || failed=`expr $failed + 1`

test_smbclient "Test login with user (ntlm)" 'ls' "$unc"  -U$USER%$NEWUSERPASS $@|| failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@02%

testit "set user password with smbpasswd" \
	test_smbpasswd $USER $NEWUSERPASS \
	|| failed=$(expr $failed + 1)

USERPASS=$NEWUSERPASS

test_smbclient "Test login with user (ntlm)" 'ls' "$unc"  -U$USER%$NEWUSERPASS $@|| failed=`expr $failed + 1`

testit "modify user - disabled"  $VALGRIND $net sam set disabled $USER yes $@ || failed=`expr $failed + 1`

testit_expect_failure  "Test login with disabled suer" $VALGRIND $smbclient //$SERVER/tmp -c 'ls' -U$USER@%$USERPASS && failed=`expr $failed + 1`

testit "modify user - enabled"  $VALGRIND $net sam set disabled $USER no $@ || failed=`expr $failed + 1`

test_smbclient "Test login with re-enabled user (ntlm)" 'ls' "$unc"  -U$USER%$NEWUSERPASS || failed=`expr $failed + 1`

testit "modify user - must change password now"  $VALGRIND $net sam set pwdmustchangenow $USER yes $@ || failed=`expr $failed + 1`

testit_expect_failure  "Test login with expired password" $VALGRIND $smbclient //$SERVER/tmp -c 'ls' -U$USER@%$USERPASS && failed=`expr $failed + 1`

testit "modify user - disable password expiry"  $VALGRIND $net sam set pwnoexp $USER yes $@ || failed=`expr $failed + 1`

test_smbclient "Test login with no expiry (ntlm)" 'ls' "$unc" -U$USER%$NEWUSERPASS || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@03%
NEWUSERHASH=062519096c45739c1938800f80906731

testit "Set user password with password hash" $VALGRIND $pdbedit -s $SMB_CONF -u $USER --set-nt-hash $NEWUSERHASH $@ || failed=`expr $failed + 1`

test_smbclient "Test login with new password (from hash)" 'ls' "$unc"  -U$USER%$NEWUSERPASS || failed=`expr $failed + 1`

testit "del user"  $VALGRIND $pdbedit -s $SMB_CONF -x $USER $@ || failed=`expr $failed + 1`

rm ./tmpsmbpasswdscript

exit $failed
