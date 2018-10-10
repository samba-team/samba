#!/bin/sh
# Blackbox tests for chainging passwords with kinit and kpasswd
#
# Copyright (c) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (c) 2006-2008 Andrew Bartlett <abartlet@samba.org>
# Copyright (c) 2016      Andreas Schneider <asn@samba.org>

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_kpasswd_mit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX
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
samba_kpasswd=kpasswd

smbclient="$samba_bindir/smbclient"
samba_tool="$samba_bindir/samba-tool"
net_tool="$samba_bindir/net"
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
	echo $password | $samba_kinit $principal
}

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

CONFIG="--configfile=$PREFIX/etc/smb.conf"
export CONFIG

testit "reset password policies beside of minimum password age of 0 days" \
	$VALGRIND $PYTHON $samba_tool domain passwordsettings set $CONFIG --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=0 --max-pwd-age=default || failed=`expr $failed + 1`

TEST_USERNAME="samson"
TEST_PASSWORD="testPaSS@00%"
TEST_PASSWORD_NEW="testPaSS@01%"
TEST_PASSWORD_SHORT="secret"
TEST_PASSWORD_WEAK="Supersecret"
TEST_PRINCIPAL="$TEST_USERNAME@$REALM"

testit "create user locally" \
	$VALGRIND $PYTHON $newuser $CONFIG $TEST_USERNAME $TEST_PASSWORD || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpuserccache"
export KRB5CCNAME

testit "kinit with user password" \
	do_kinit $TEST_PRINCIPAL $TEST_PASSWORD || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" \
	"ls" "$SMB_UNC" -k yes || failed=`expr $failed + 1`

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
### check that a password mismatch is detected
###########################################################

cat > $PREFIX/tmpkpasswdscript <<EOF
expect Password for $TEST_PRINCIPAL
password ${TEST_PASSWORD}\n
expect Enter new password
send ${TEST_PASSWORD_WEAK}\n
expect Enter it again
send ${TEST_PASSWORD_NEW}\n
expect kpasswd: Password mismatch while reading password
EOF

testit_expect_failure "kpasswd check password mismatch" \
	$texpect $PREFIX/tmpkpasswdscript $samba_kpasswd $TEST_PRINCIPAL && failed=`expr $failed + 1`

###########################################################
### check that a short password is rejected
###########################################################

cat > $PREFIX/tmpkpasswdscript <<EOF
expect Password for $TEST_PRINCIPAL
password ${TEST_PASSWORD}\n
expect Enter new password
send ${TEST_PASSWORD_SHORT}\n
expect Enter it again
send ${TEST_PASSWORD_SHORT}\n
expect Password change rejected: Password too short, password must be at least 7 characters long
EOF

testit_expect_failure "kpasswd check short user password" \
	$texpect $PREFIX/tmpkpasswdscript $samba_kpasswd $TEST_PRINCIPAL && failed=`expr $failed + 1`

###########################################################
### check that a weak password is rejected
###########################################################

cat > $PREFIX/tmpkpasswdscript <<EOF
expect Password for $TEST_PRINCIPAL
password ${TEST_PASSWORD}\n
expect Enter new password
send ${TEST_PASSWORD_WEAK}\n
expect Enter it again
send ${TEST_PASSWORD_WEAK}\n
expect Password change rejected: Password does not meet complexity requirement
EOF

testit_expect_failure "kpasswd check weak user password" \
	$texpect $PREFIX/tmpkpasswdscript $samba_kpasswd $TEST_PRINCIPAL && failed=`expr $failed + 1`

###########################################################
### check that a strong password is accepted
###########################################################

cat > $PREFIX/tmpkpasswdscript <<EOF
expect Password for $TEST_PRINCIPAL
password ${TEST_PASSWORD}\n
expect Enter new password
send ${TEST_PASSWORD_NEW}\n
expect Enter it again
send ${TEST_PASSWORD_NEW}\n
expect Password changed.
EOF

testit "kpasswd change user password" \
	$texpect $PREFIX/tmpkpasswdscript $samba_kpasswd $TEST_PRINCIPAL|| failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@03%"

test_smbclient "Test login with user kerberos" 'ls' "$SMB_UNC" -k yes -U$TEST_PRINCIPAL%$TEST_PASSWORD || failed=`expr $failed + 1`

###########################################################
### Force password change at login
###########################################################

testit "set password on user locally" \
	$VALGRIND $PYTHON $samba_tool user setpassword $TEST_USERNAME $CONFIG --newpassword=$TEST_PASSWORD_NEW --must-change-at-next-login || failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@04%"

cat > $PREFIX/tmpkinitscript <<EOF
expect Password for $TEST_PRINCIPAL
password ${TEST_PASSWORD}\n
expect Password expired
expect Enter new password
send ${TEST_PASSWORD_NEW}\n
expect Enter it again
send ${TEST_PASSWORD_NEW}\n
EOF

testit "kinit and change user password" \
	$texpect $PREFIX/tmpkinitscript $samba_kinit $TEST_PRINCIPAL|| failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@05%"

test_smbclient "Test login with user kerberos" \
	"ls" "$SMB_UNC" -k yes -U$TEST_PRINCIPAL%$TEST_PASSWORD || failed=`expr $failed + 1`

###########################################################
### Test kpasswd service via 'net ads password'
###########################################################

testit "change user password with 'net ads password', admin: $DOMAIN/$TEST_USERNAME, target: $TEST_PRINCIPAL" \
	$VALGRIND $net_tool ads password -W$DOMAIN -U$TEST_PRINCIPAL%$TEST_PASSWORD $TEST_PRINCIPAL "$TEST_PASSWORD_NEW" || failed=`expr $failed + 1`

#TEST_PASSWORD=$TEST_PASSWORD_NEW
#TEST_PASSWORD_NEW="testPaSS@06%"

#test_smbclient "Test login with smbclient (ntlm)" \
#	"ls" "$SMB_UNC" -k no -U$TEST_PRINCIPAL%$TEST_PASSWORD || failed=`expr $failed + 1`

###########################################################
### Test kpasswd service via 'net ads password' as admin
###########################################################

testit "set user password with 'net ads password', admin: $DOMAIN/$USERNAME, target: $TEST_PRINCIPAL" \
	$VALGRIND $net_tool ads password -W$DOMAIN -U$USERNAME@$REALM%$PASSWORD $TEST_PRINCIPAL "$TEST_PASSWORD_NEW" || failed=`expr $failed + 1`

TEST_PASSWORD=$TEST_PASSWORD_NEW
TEST_PASSWORD_NEW="testPaSS@07%"

test_smbclient "Test login with smbclient (ntlm)" \
	"ls" "$SMB_UNC" -k no -U$TEST_PRINCIPAL%$TEST_PASSWORD || failed=`expr $failed + 1`

###########################################################
### Cleanup
###########################################################

testit "reset password policies" \
	$VALGRIND $PYTHON $samba_tool domain passwordsettings set $CONFIG --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=default --max-pwd-age=default || failed=`expr $failed + 1`

testit "delete user" \
	$VALGRIND $PYTHON $samba_tool user delete $TEST_USERNAME -U"$USERNAME%$PASSWORD" $CONFIG -k no  || failed=`expr $failed + 1`

rm -f $PREFIX/tmpuserccache $PREFIX/tmpkpasswdscript $PREFIX/tmpkinitscript
exit $failed
