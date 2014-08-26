#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_passwords.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX SMBCLIENT
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
PREFIX=$6
smbclient=$7
shift 7
failed=0

samba4bindir="$BINDIR"
samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi

samba_tool="$samba4bindir/samba-tool"
net_tool="$samba4bindir/net"
smbpasswd="$samba4bindir/smbpasswd"
texpect="$samba4bindir/texpect"
samba4kpasswd=kpasswd
if test -x $BINDIR/samba4kpasswd; then
	samba4kpasswd=$BINDIR/samba4kpasswd
fi

newuser="$samba_tool user create"

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

do_kinit() {
	file="$1"
	password="$2"
	shift
	shift
	if test -x $BINDIR/samba4kinit; then
		$samba4kinit --password-file=$file --request-pac $@
	else
		echo $password | $samba4kinit $@
	fi
}

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

CONFIG="--configfile=$PREFIX/dc/etc/smb.conf"
export CONFIG

testit "reset password policies beside of minimum password age of 0 days" $VALGRIND $samba_tool domain passwordsettings $CONFIG set --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=0 --max-pwd-age=default || failed=`expr $failed + 1`

USERPASS=testPaSS@00%

testit "create user locally" $VALGRIND $newuser $CONFIG nettestuser $USERPASS $@ || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmpuserccache"
export KRB5CCNAME

echo $USERPASS > $PREFIX/tmpuserpassfile

testit "kinit with user password" do_kinit $PREFIX/tmpuserpassfile $USERPASS nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@01%
testit "change user password with 'samba-tool user password' (unforced)" $VALGRIND $samba_tool user password -W$DOMAIN -U$DOMAIN/nettestuser%$USERPASS  -k no --newpassword=$NEWUSERPASS $@ || failed=`expr $failed + 1`

echo $NEWUSERPASS > ./tmpuserpassfile
testit "kinit with user password" do_kinit ./tmpuserpassfile $NEWUSERPASS nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

#
# These tests demonstrate that a credential cache in the environment does not
# override a username/password, even an incorrect one, on the command line
#

testit_expect_failure  "Test login with user kerberos ccache, but wrong password specified" $VALGRIND $smbclient //$SERVER/tmp -c 'ls' -k yes -Unettestuser@$REALM%wrongpass && failed=`expr $failed + 1`
testit_expect_failure  "Test login with user kerberos ccache, but old password specified" $VALGRIND $smbclient //$SERVER/tmp -c 'ls' -k yes -Unettestuser@$REALM%$USERPASS && failed=`expr $failed + 1`


USERPASS=$NEWUSERPASS
WEAKPASS=testpass1
NEWUSERPASS=testPaSS@02%

# password mismatch check doesn't work yet (kpasswd bug, reported to Love)
#echo "check that password mismatch gives the right error"
#cat > ./tmpkpasswdscript <<EOF
#expect Password
#password ${USERPASS}\n
#expect New password
#send ${WEAKPASS}\n
#expect New password
#send ${NEWUSERPASS}\n
#expect password mismatch
#EOF
#
#testit "change user password with kpasswd" $texpect ./tmpkpasswdscript $samba4kpasswd nettestuser@$REALM || failed=`expr $failed + 1`


echo "check that a weak password is rejected"
cat > ./tmpkpasswdscript <<EOF
expect Password
password ${USERPASS}\n
expect New password
send ${WEAKPASS}\n
expect New password
send ${WEAKPASS}\n
expect Password does not meet complexity requirements
EOF

testit "change to weak user password with kpasswd" $texpect ./tmpkpasswdscript $samba4kpasswd nettestuser@$REALM || failed=`expr $failed + 1`

echo "check that a short password is rejected"
cat > ./tmpkpasswdscript <<EOF
expect Password
password ${USERPASS}\n
expect New password
send xx1\n
expect New password
send xx1\n
expect Password too short
EOF

testit "change to short user password with kpasswd" $texpect ./tmpkpasswdscript $samba4kpasswd nettestuser@$REALM || failed=`expr $failed + 1`


echo "check that a strong new password is accepted"
cat > ./tmpkpasswdscript <<EOF
expect Password
password ${USERPASS}\n
expect New password
send ${NEWUSERPASS}\n
expect New password
send ${NEWUSERPASS}\n
expect Success
EOF

testit "change user password with kpasswd" $texpect ./tmpkpasswdscript $samba4kpasswd nettestuser@$REALM || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos (unforced)" 'ls' -k yes -Unettestuser@$REALM%$NEWUSERPASS || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@03%

echo "set password with smbpasswd"
cat > ./tmpsmbpasswdscript <<EOF
expect New SMB password:
send ${NEWUSERPASS}\n
expect Retype new SMB password:
send ${NEWUSERPASS}\n
EOF

testit "set user password with smbpasswd" $texpect ./tmpsmbpasswdscript $smbpasswd -L -c $PREFIX/dc/etc/smb.conf nettestuser || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

test_smbclient "Test login with user (ntlm)" 'ls' -k no -Unettestuser@$REALM%$NEWUSERPASS || failed=`expr $failed + 1`


NEWUSERPASS=testPaSS@04%
testit "set password on user locally" $VALGRIND $samba_tool user setpassword nettestuser $CONFIG --newpassword=$NEWUSERPASS --must-change-at-next-login $@ || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

NEWUSERPASS=testPaSS@05%
testit "change user password with 'samba-tool user password' (after must change flag set)" $VALGRIND $samba_tool user password -W$DOMAIN -U$DOMAIN/nettestuser%$USERPASS -k no --newpassword=$NEWUSERPASS $@ || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

NEWUSERPASS=testPaSS@06%
testit "set password on user locally" $VALGRIND $samba_tool user setpassword $CONFIG nettestuser --newpassword=$NEWUSERPASS --must-change-at-next-login $@ || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

NEWUSERPASS=testPaSS@07%

cat > ./tmpkpasswdscript <<EOF
expect Password
password ${USERPASS}\n
expect New password
send ${NEWUSERPASS}\n
expect New password
send ${NEWUSERPASS}\n
expect Success
EOF

testit "change user password with kpasswd (after must change flag set)" $texpect ./tmpkpasswdscript $samba4kpasswd nettestuser@$REALM || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

test_smbclient "Test login with user kerberos" 'ls' -k yes -Unettestuser@$REALM%$NEWUSERPASS || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@08%
testit "set password on user locally" $VALGRIND $samba_tool user setpassword $CONFIG nettestuser --newpassword=$NEWUSERPASS --must-change-at-next-login $@ || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

NEWUSERPASS=testPaSS@09%

cat > ./tmpsmbpasswdscript <<EOF
expect Old SMB password:
password ${USERPASS}\n
expect New SMB password:
send ${NEWUSERPASS}\n
expect Retype new SMB password:
send ${NEWUSERPASS}\n
EOF

testit "change user password with smbpasswd (after must change flag set)" $texpect ./tmpsmbpasswdscript $smbpasswd -r $SERVER  -c $PREFIX/dc/etc/smb.conf -U nettestuser || failed=`expr $failed + 1`

USERPASS=$NEWUSERPASS

test_smbclient "Test login with user kerberos" 'ls' -k yes -Unettestuser@$REALM%$NEWUSERPASS || failed=`expr $failed + 1`

NEWUSERPASS=abcdefg
testit_expect_failure "try to set a non-complex password (command should not succeed)" $VALGRIND $samba_tool user password -W$DOMAIN "-U$DOMAIN/nettestuser%$USERPASS" -k no --newpassword="$NEWUSERPASS" $@ && failed=`expr $failed + 1`

testit "allow non-complex passwords" $VALGRIND $samba_tool domain passwordsettings set $CONFIG --complexity=off || failed=`expr $failed + 1`

testit "try to set a non-complex password (command should succeed)" $VALGRIND $samba_tool user password -W$DOMAIN "-U$DOMAIN/nettestuser%$USERPASS" -k no --newpassword="$NEWUSERPASS" $@ || failed=`expr $failed + 1`
USERPASS=$NEWUSERPASS

test_smbclient "test login with non-complex password" 'ls' -k no -Unettestuser@$REALM%$USERPASS || failed=`expr $failed + 1`

NEWUSERPASS=abc
testit_expect_failure "try to set a short password (command should not succeed)" $VALGRIND $samba_tool user password -W$DOMAIN "-U$DOMAIN/nettestuser%$USERPASS" -k no --newpassword="$NEWUSERPASS" $@ && failed=`expr $failed + 1`

testit "allow short passwords (length 1)" $VALGRIND $samba_tool domain passwordsettings $CONFIG set --min-pwd-length=1 || failed=`expr $failed + 1`

testit "try to set a short password (command should succeed)" $VALGRIND $samba_tool user password -W$DOMAIN "-U$DOMAIN/nettestuser%$USERPASS" -k no --newpassword="$NEWUSERPASS" $@ || failed=`expr $failed + 1`
USERPASS="$NEWUSERPASS"

# test kpasswd via net ads password (change variant)
NEWUSERPASS="testPaSS@10%"
testit "change user password with 'net ads password', admin: $DOMAIN/nettestuser, target: nettestuser@$REALM" $VALGRIND $net_tool ads password -W$DOMAIN -Unettestuser@$REALM%$USERPASS nettestuser@$REALM "$NEWUSERPASS" $@ || failed=`expr $failed + 1`
USERPASS="$NEWUSERPASS"

test_smbclient "Test login with smbclient" 'ls' -k no -Unettestuser@$REALM%$NEWUSERPASS || failed=`expr $failed + 1`

# test kpasswd via net ads password (admin set variant)
NEWUSERPASS="testPaSS@11%"
testit "set user password with 'net ads password', admin: $DOMAIN/$USERNAME, target: nettestuser@$REALM" $VALGRIND $net_tool ads password -W$DOMAIN -U$USERNAME@$REALM%$PASSWORD nettestuser@$REALM "$NEWUSERPASS" $@ || failed=`expr $failed + 1`
USERPASS="$NEWUSERPASS"

test_smbclient "Test login with smbclient" 'ls' -k no -Unettestuser@$REALM%$NEWUSERPASS || failed=`expr $failed + 1`

testit "require minimum password age of 1 day" $VALGRIND $samba_tool domain passwordsettings $CONFIG set --min-pwd-age=1 || failed=`expr $failed + 1`

testit "show password settings" $VALGRIND $samba_tool domain passwordsettings $CONFIG show || failed=`expr $failed + 1`

NEWUSERPASS="testPaSS@08%"
testit_expect_failure "try to change password too quickly (command should not succeed)" $VALGRIND $samba_tool user password -W$DOMAIN "-U$DOMAIN/nettestuser%$USERPASS" -k no --newpassword="$NEWUSERPASS" $@ && failed=`expr $failed + 1`

testit "reset password policies" $VALGRIND $samba_tool domain passwordsettings $CONFIG set --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=default --max-pwd-age=default || failed=`expr $failed + 1`

testit "del user" $VALGRIND $samba_tool user delete nettestuser -U"$USERNAME%$PASSWORD" $CONFIG -k no $@ || failed=`expr $failed + 1`

rm -f tmpccfile tmppassfile tmpuserpassfile tmpuserccache tmpkpasswdscript tmpsmbpasswdscript
exit $failed
