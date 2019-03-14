#!/bin/sh
# Blackbox tests for different password settings
#
# Copyright (c) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (c) 2006-2008 Andrew Bartlett <abartlet@samba.org>
# Copyright (c) 2016      Andreas Schneider <asn@samba.org>

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_passwords_settings.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX
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

samba_bindir="$BINDIR"

samba_kinit=kinit
if test -x $samba_bindir/samba4kinit; then
	samba_kinit=$samba_bindir/samba4kinit
fi

smbclient="$samba_bindir/smbclient"
samba_tool="$samba_bindir/samba-tool"
smbpasswd="$samba_bindir/smbpasswd"
texpect="$samba_bindir/texpect"

newuser="$samba_tool user create"
SMB_UNC="//$SERVER/tmp"

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

do_kinit() {
	principal="$1"
	password="$2"
	shift
	shift
	if test -x $samba_bindir/samba4kinit; then
		echo $password > $PREFIX/tmpuserpassfile
		$samba_kinit --password-file=$PREFIX/tmpuserpassfile $principal $@
	else
		echo $password | $samba_kinit $principal $@
	fi
}

test_smbpasswd()
{
	user=$1
	newpass=$2

	tmpfile=$PREFIX/smbpasswd_change_password_script
	cat > $tmpfile <<EOF
expect New SMB password:
send ${newpass}\n
expect Retype new SMB password:
send ${newpass}\n
EOF

	cmd='UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $texpect $tmpfile $smbpasswd -L -c $PREFIX/etc/smb.conf $user'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "Failed to change user password $user"
		return 1
	fi
}

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

CONFIG="--configfile=$PREFIX/etc/smb.conf"
export CONFIG

testit "reset password policies beside of minimum password age of 0 days" \
	$VALGRIND $PYTHON $samba_tool domain passwordsettings set $CONFIG --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=0 --max-pwd-age=default || failed=`expr $failed + 1`

TEST_USERNAME="$(mktemp -u alice-XXXXXX)"
TEST_PASSWORD="testPaSS@00%"
TEST_PASSWORD_NEW="testPaSS@01%"
TEST_PASSWORD_NON_ASCII="Täst123"
TEST_PASSWORD_SHORT="secret"
TEST_PASSWORD_WEAK="Supersecret"
TEST_PRINCIPAL="$TEST_USERNAME@$REALM"

testit "create user locally" \
	$VALGRIND $PYTHON $newuser $CONFIG $TEST_USERNAME $TEST_PASSWORD || failed=`expr $failed + 1`

###########################################################
### Test normal operation as user
###########################################################

KRB5CCNAME_PATH="$PREFIX/test_password_settings_krb5ccache"
rm -f $KRB5CCNAME_PATH

KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

testit "kinit with user password" \
	do_kinit $TEST_PRINCIPAL $TEST_PASSWORD || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" \
	"ls" "$SMB_UNC" -k yes || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH

###########################################################
### Change the users password
###########################################################

testit "change user password with 'samba-tool user password' (unforced)" \
	$VALGRIND $PYTHON $samba_tool user password -W$DOMAIN -U$TEST_USERNAME%$TEST_PASSWORD -k no --newpassword=$TEST_PASSWORD_NEW || failed=`expr $failed + 1`

TEST_PASSWORD_OLD=$TEST_PASSWORD
TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@02%"

testit "kinit with user password" \
	do_kinit $TEST_PRINCIPAL $TEST_PASSWORD || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" \
	"ls" "$SMB_UNC" -k yes || failed=`expr $failed + 1`

###########################################################
### Change the users password
###########################################################

testit "change user (non-ascii) password with 'samba-tool user password' (unforced)" \
	$VALGRIND $PYTHON $samba_tool user password -W$DOMAIN -U$TEST_USERNAME%$TEST_PASSWORD -k no --newpassword=$TEST_PASSWORD_NON_ASCII || failed=`expr $failed + 1`

TEST_PASSWORD_OLD=$TEST_PASSWORD_NEW
TEST_PASSWORD=$TEST_PASSWORD_NON_ASCII

testit "kinit with user password" \
	do_kinit $TEST_PRINCIPAL $TEST_PASSWORD || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" \
	"ls" "$SMB_UNC" -k yes || failed=`expr $failed + 1`

#
# These tests demonstrate that a credential cache in the environment does not
# override a username/password, even an incorrect one, on the command line
#

testit_expect_failure "Test login with user kerberos ccache, but wrong password specified" \
	$VALGRIND $smbclient //$SERVER/tmp -c 'ls' -k yes -U$TEST_PRINCIPAL%invalidpass && failed=`expr $failed + 1`
testit_expect_failure "Test login with user kerberos ccache, but old password specified" \
	$VALGRIND $smbclient //$SERVER/tmp -c 'ls' -k yes -U$TEST_PRINCIPAL%$TEST_PASSWORD_OLD && failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH

###########################################################
### Set the password with smbpasswd
###########################################################

testit "set user password with smbpasswd" \
	test_smbpasswd $TEST_USERNAME $TEST_PASSWORD_NEW \
	|| failed=$(expr $failed + 1)

TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@03%"

test_smbclient "Test login with user (ntlm)" \
	"ls" "$SMB_UNC" -k no -U$TEST_PRINCIPAL%$TEST_PASSWORD || failed=`expr $failed + 1`

testit "set password on user locally" $VALGRIND $PYTHON $samba_tool user setpassword $TEST_USERNAME $CONFIG --newpassword=$TEST_PASSWORD_NEW --must-change-at-next-login || failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@04%"

test_smbclient_expect_failure "Test login with user (NT_STATUS_PASSWORD_MUST_CHANGE)" \
	"ls" "$SMB_UNC" -k no -U$TEST_PRINCIPAL%$TEST_PASSWORD && failed=`expr $failed + 1`

testit "change user password with 'samba-tool user password' (after must change flag set)" \
	$VALGRIND $PYTHON $samba_tool user password -W$DOMAIN -U$DOMAIN/$TEST_USERNAME%$TEST_PASSWORD -k no --newpassword=$TEST_PASSWORD_NEW || failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@05%"

test_smbclient "Test login with user kerberos" 'ls' "$SMB_UNC" -k yes -U$TEST_PRINCIPAL%$TEST_PASSWORD || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH

cat > $PREFIX/tmpsmbpasswdscript <<EOF
expect Old SMB password:
password ${TEST_PASSWORD}\n
expect New SMB password:
send ${TEST_PASSWORD_NEW}\n
expect Retype new SMB password:
send ${TEST_PASSWORD_NEW}\n
EOF

testit "change user password with smbpasswd (after must change flag set)" \
	$texpect $PREFIX/tmpsmbpasswdscript $smbpasswd -r $SERVER  -c $PREFIX/etc/smb.conf -U $TEST_USERNAME || failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@06%"

test_smbclient "Test login with user kerberos" \
	"ls" "$SMB_UNC" -k yes -U$TEST_PRINCIPAL%$TEST_PASSWORD || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH

testit_expect_failure "try to set a non-complex password (command should not succeed)" \
	$VALGRIND $PYTHON $samba_tool user password -W$DOMAIN "-U$DOMAIN/$TEST_USERNAME%$TEST_PASSWORD" -k no --newpassword="$TEST_PASSWORD_WEAK" && failed=`expr $failed + 1`

testit "allow non-complex passwords" \
	$VALGRIND $PYTHON $samba_tool domain passwordsettings set $CONFIG --complexity=off || failed=`expr $failed + 1`

testit "try to set a non-complex password (command should succeed)" \
	$VALGRIND $PYTHON $samba_tool user password -W$DOMAIN "-U$DOMAIN/$TEST_USERNAME%$TEST_PASSWORD" -k no --newpassword="$TEST_PASSWORD_WEAK" || failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_WEAK

test_smbclient "test login with non-complex password" \
	"ls" "$SMB_UNC" -k no -U$TEST_PRINCIPAL%$TEST_PASSWORD || failed=`expr $failed + 1`

testit_expect_failure "try to set a short password (command should not succeed)" \
	$VALGRIND $PYTHON $samba_tool user password -W$DOMAIN "-U$DOMAIN/$TEST_USERNAME%$TEST_PASSWORD" -k no --newpassword="$TEST_PASSWORD_SHORT" && failed=`expr $failed + 1`

testit "allow short passwords (length 1)" \
	$VALGRIND $PYTHON $samba_tool domain passwordsettings set $CONFIG --min-pwd-length=1 || failed=`expr $failed + 1`

testit "try to set a short password (command should succeed)" \
	$VALGRIND $PYTHON $samba_tool user password -W$DOMAIN "-U$DOMAIN/$TEST_USERNAME%$TEST_PASSWORD" -k no --newpassword="$TEST_PASSWORD_SHORT" || failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_SHORT
TEST_PASSWORD_NEW="testPaSS@07%"

testit "require minimum password age of 1 day" \
	$VALGRIND $PYTHON $samba_tool domain passwordsettings set $CONFIG --min-pwd-age=1 || failed=`expr $failed + 1`

testit "show password settings" \
	$VALGRIND $PYTHON $samba_tool domain passwordsettings show $CONFIG || failed=`expr $failed + 1`

testit_expect_failure "try to change password too quickly (command should not succeed)" \
	$VALGRIND $PYTHON $samba_tool user password -W$DOMAIN "-U$DOMAIN/$TEST_USERNAME%$TEST_PASSWORD" -k no --newpassword="$TEST_PASSWORD_NEW"  && failed=`expr $failed + 1`

testit "reset password policies" \
	$VALGRIND $PYTHON $samba_tool domain passwordsettings set $CONFIG --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=default --max-pwd-age=default || failed=`expr $failed + 1`

testit "delete user $TEST_USERNAME" \
	$VALGRIND $PYTHON $samba_tool user delete $TEST_USERNAME -U"$USERNAME%$PASSWORD" $CONFIG -k no  || failed=`expr $failed + 1`

rm -f $PREFIX/tmpuserpassfile $PREFIX/tmpsmbpasswdscript
rm -f $KRB5CCNAME_PATH

exit $failed
