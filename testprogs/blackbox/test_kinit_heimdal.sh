#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX ENCTYPE SMBCLIENT
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
samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi

samba_tool="$samba4bindir/samba-tool"
texpect="$samba4bindir/texpect"
samba4kpasswd=kpasswd
if test -x $BINDIR/samba4kpasswd; then
	samba4kpasswd=$BINDIR/samba4kpasswd
fi

enableaccount="$samba_tool user enable"
machineaccountccache="$samba4srcdir/scripting/bin/machineaccountccache"

ldbmodify="ldbmodify"
if [ -x "$samba4bindir/ldbmodify" ]; then
	ldbmodify="$samba4bindir/ldbmodify"
fi

ldbsearch="ldbsearch"
if [ -x "$samba4bindir/ldbsearch" ]; then
	ldbsearch="$samba4bindir/ldbsearch"
fi

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

enctype="-e $ENCTYPE"
unc="//$SERVER/tmp"

ADMIN_LDBMODIFY_CONFIG="-H ldap://$SERVER -U$USERNAME%$PASSWORD"
export ADMIN_LDBMODIFY_CONFIG

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
ADMIN_KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -rf $KRB5CCNAME_PATH

testit "reset password policies beside of minimum password age of 0 days" $VALGRIND $PYTHON $samba_tool domain passwordsettings set $ADMIN_LDBMODIFY_CONFIG --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=0 --max-pwd-age=default || failed=`expr $failed + 1`

echo $PASSWORD > $PREFIX/tmppassfile
testit "kinit with password" $samba4kinit $enctype --password-file=$PREFIX/tmppassfile --request-pac $USERNAME@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

testit "kinit with password (enterprise style)" $samba4kinit $enctype --enterprise --password-file=$PREFIX/tmppassfile --request-pac $USERNAME@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

testit "kinit with password (windows style)" $samba4kinit $enctype  --renewable --windows --password-file=$PREFIX/tmppassfile --request-pac $USERNAME@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

testit "kinit renew ticket" $samba4kinit $enctype --request-pac -R

test_smbclient "Test login with kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

testit "check time with kerberos ccache" $VALGRIND $PYTHON $samba_tool time $SERVER $CONFIGURATION -k yes $@ || failed=`expr $failed + 1`

USERPASS=testPass@12%
echo $USERPASS > $PREFIX/tmpuserpassfile
testit "add user with kerberos ccache" $VALGRIND $PYTHON $samba_tool user create nettestuser $USERPASS $CONFIGURATION  -k yes $@ || failed=`expr $failed + 1`

echo "Getting defaultNamingContext"
BASEDN=`$ldbsearch $options --basedn='' -H ldap://$SERVER -s base DUMMY=x defaultNamingContext | grep defaultNamingContext | awk '{print $2}'`

cat > $PREFIX/tmpldbmodify <<EOF
dn: cn=nettestuser,cn=users,$BASEDN
changetype: modify
add: servicePrincipalName
servicePrincipalName: host/nettestuser
replace: userPrincipalName
userPrincipalName: nettest@$REALM
EOF

testit "modify servicePrincipalName and userPrincpalName" $VALGRIND $ldbmodify -H ldap://$SERVER $PREFIX/tmpldbmodify -k yes $@ || failed=`expr $failed + 1`

testit "set user password with kerberos ccache" $VALGRIND $PYTHON $samba_tool user setpassword nettestuser --newpassword=$USERPASS $CONFIGURATION  -k yes $@ || failed=`expr $failed + 1`

testit "enable user with kerberos cache" $VALGRIND $PYTHON $enableaccount nettestuser -H ldap://$SERVER -k yes $@ || failed=`expr $failed + 1`

KRB5CCNAME_PATH="$PREFIX/tmpuserccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

rm -f $KRB5CCNAME_PATH
testit "kinit with user password" $samba4kinit $enctype --password-file=$PREFIX/tmpuserpassfile --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@34%
testit "change user password with 'samba-tool user password' (rpc)" $VALGRIND $PYTHON $samba_tool user password -W$DOMAIN -Unettestuser%$USERPASS $CONFIGURATION -k no --newpassword=$NEWUSERPASS $@ || failed=`expr $failed + 1`

echo $NEWUSERPASS > $PREFIX/tmpuserpassfile
rm -f $KRB5CCNAME_PATH
testit "kinit with user password" $samba4kinit $enctype --password-file=$PREFIX/tmpuserpassfile --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`


rm -f $KRB5CCNAME_PATH
testit "kinit with password (NT-Principal style) using UPN" $samba4kinit $enctype --password-file=$PREFIX/tmpuserpassfile --request-pac nettest@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache from enterprise UPN" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH
testit "kinit with password (enterprise style) using UPN" $samba4kinit $enctype --enterprise --password-file=$PREFIX/tmpuserpassfile --request-pac nettest@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache from enterprise UPN" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH
testit "kinit with password (windows style) using UPN" $samba4kinit $enctype  --renewable --windows --password-file=$PREFIX/tmpuserpassfile --request-pac nettest@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache from windows UPN" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

cat > $PREFIX/tmpldbmodify <<EOF
dn: cn=nettestuser,cn=users,$BASEDN
changetype: modify
replace: userPrincipalName
userPrincipalName: nettest@$REALM.org
EOF

testit "modify userPrincipalName to be a different domain" $VALGRIND $ldbmodify $ADMIN_LDBMODIFY_CONFIG $PREFIX/tmpldbmodify $PREFIX/tmpldbmodify -k yes $@ || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH
testit "kinit with password (enterprise style) using UPN" $samba4kinit $enctype --enterprise --password-file=$PREFIX/tmpuserpassfile --request-pac nettest@$REALM.org   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache from enterprise UPN, different domain" 'ls' "$unc" -k yes || failed=`expr $failed + 1`


USERPASS=$NEWUSERPASS
NEWUSERPASS=testPaSS@56%
echo $NEWUSERPASS > $PREFIX/tmpuserpassfile

cat > $PREFIX/tmpkpasswdscript <<EOF
expect Password
password ${USERPASS}\n
expect New password
send ${NEWUSERPASS}\n
expect Verify password
send ${NEWUSERPASS}\n
expect Success
EOF

testit "change user password with kpasswd" $texpect $PREFIX/tmpkpasswdscript $samba4kpasswd nettestuser@$REALM || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH
testit "kinit with user password" $samba4kinit $enctype --password-file=$PREFIX/tmpuserpassfile --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@78%
echo $NEWUSERPASS > $PREFIX/tmpuserpassfile

test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

cat > $PREFIX/tmpkpasswdscript <<EOF
expect New password
send ${NEWUSERPASS}\n
expect Verify password
send ${NEWUSERPASS}\n
expect Success
EOF

testit "set user password with kpasswd" $texpect $PREFIX/tmpkpasswdscript $samba4kpasswd --cache=$ADMIN_KRB5CCNAME nettestuser@$REALM || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH
testit "kinit with user password" $samba4kinit $enctype --password-file=$PREFIX/tmpuserpassfile --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

NEWUSERPASS=testPaSS@910%
echo $NEWUSERPASS > $PREFIX/tmpuserpassfile

cat > $PREFIX/tmpkpasswdscript <<EOF
expect New password
send ${NEWUSERPASS}\n
expect Verify password
send ${NEWUSERPASS}\n
expect Success
EOF

testit "set user password with kpasswd and servicePrincipalName" $texpect $PREFIX/tmpkpasswdscript $samba4kpasswd --cache=$PREFIX/tmpccache host/nettestuser@$REALM || failed=`expr $failed + 1`

testit "kinit with user password" $samba4kinit $enctype --password-file=$PREFIX/tmpuserpassfile --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

cat > $PREFIX/tmpldbmodify <<EOF
dn: cn=nettestuser,cn=users,$BASEDN
changetype: modify
replace: pwdLastSet
pwdLastSet: 0
EOF

USERPASS=$NEWUSERPASS
NEWUSERPASS=testPaSS@911%

testit "modify pwdLastSet" $VALGRIND $ldbmodify $ADMIN_LDBMODIFY_CONFIG $PREFIX/tmpldbmodify $PREFIX/tmpldbmodify -k yes $@ || failed=`expr $failed + 1`

cat > $PREFIX/tmppasswordchange <<EOF
expect nettestuser@${REALM}'s Password:
send ${USERPASS}\n
expect Your password will expire at
expect Changing password
expect New password:
send ${NEWUSERPASS}\n
expect Repeat new password:
send ${NEWUSERPASS}\n
expect Success: Password changed
EOF

testit "kinit with user password for expired password" $texpect $PREFIX/tmppasswordchange $samba4kinit $enctype --request-pac nettestuser@$REALM && failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

echo $NEWUSERPASS > $PREFIX/tmpuserpassfile
testit "kinit with user password" $samba4kinit $enctype --password-file=$PREFIX/tmpuserpassfile --request-pac nettestuser@$REALM   || failed=`expr $failed + 1`

test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

rm -rf $KRB5CCNAME_PATH

lowerrealm=$(echo $REALM | tr '[A-Z]' '[a-z]')
test_smbclient "Test login with user kerberos lowercase realm" 'ls' "$unc" -k yes -Unettestuser@$lowerrealm%$NEWUSERPASS || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos lowercase realm 2" 'ls' "$unc" -k yes -Unettestuser@$REALM%$NEWUSERPASS --realm=$lowerrealm || failed=`expr $failed + 1`

testit "del user with kerberos ccache" $VALGRIND $PYTHON $samba_tool user delete nettestuser $CONFIGURATION -k yes $@ || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH
testit "kinit with machineaccountccache script" $PYTHON $machineaccountccache $CONFIGURATION $KRB5CCNAME || failed=`expr $failed + 1`
test_smbclient "Test machine account login with kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

testit "reset password policies" $VALGRIND $PYTHON $samba_tool domain passwordsettings set $ADMIN_LDBMODIFY_CONFIG --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=default --max-pwd-age=default || failed=`expr $failed + 1`

rm -f $PREFIX/tmpccache tmpccfile tmppassfile tmpuserpassfile tmpuserccache tmpkpasswdscript
exit $failed
