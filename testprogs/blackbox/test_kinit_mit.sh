#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (c) 2015-2016 Andreas Schneider <asn@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX SMBCLIENT
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

samba_bindir="$BINDIR"
samba_srcdir="$SRCDIR/source4"
samba_kinit=kinit
samba_kdestroy=kdestroy
samba_kpasswd=kpasswd

samba_tool="$samba_bindir/samba-tool"
samba_texpect="$samba_bindir/texpect"

samba_enableaccount="$samba_tool user enable"
machineaccountccache="$samba_srcdir/scripting/bin/machineaccountccache"

ldbmodify="ldbmodify"
if [ -x "$samba4bindir/ldbmodify" ]; then
	ldbmodify="$samba4bindir/ldbmodify"
fi

ldbsearch="ldbsearch"
if [ -x "$samba4bindir/ldbsearch" ]; then
	ldbsearch="$samba4bindir/ldbsearch"
fi

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

ADMIN_LDBMODIFY_CONFIG="-H ldap://$SERVER -U$USERNAME%$PASSWORD"
export ADMIN_LDBMODIFY_CONFIG

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
ADMIN_KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -rf $KRB5CCNAME_PATH

testit "reset password policies beside of minimum password age of 0 days" $VALGRIND $samba_tool domain passwordsettings $ADMIN_LDBMODIFY_CONFIG set --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=0 --max-pwd-age=default || failed=`expr $failed + 1`

cat > $PREFIX/tmpkinitscript <<EOF
expect Password for
send ${PASSWORD}\n
EOF

###########################################################
### Test kinit defaults
###########################################################

testit "kinit with password" $samba_texpect $PREFIX/tmpkinitscript $samba_kinit $USERNAME@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

testit "kinit renew ticket" $samba_kinit -R   || failed=`expr $failed + 1`
test_smbclient "Test login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

$samba_kdestroy

###########################################################
### Test kinit with enterprice principal
###########################################################

testit "kinit with password (enterprise style)" $samba_texpect $PREFIX/tmpkinitscript $samba_kinit -E $USERNAME@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

# This does not work with MIT Kerberos 1.14 or older
testit "kinit renew ticket (enterprise style)" $samba_kinit -R   || failed=`expr $failed + 1`
test_smbclient "Test login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

$samba_kdestroy

###########################################################
### Tests with kinit default again
###########################################################

testit "kinit with password" $samba_texpect $PREFIX/tmpkinitscript $samba_kinit $USERNAME@$REALM   || failed=`expr $failed + 1`
testit "check time with kerberos ccache" $VALGRIND $samba_tool time $SERVER $CONFIGURATION -k yes $@ || failed=`expr $failed + 1`

USERPASS="testPass@12%"

testit "add user with kerberos ccache" $VALGRIND $samba_tool user create nettestuser $USERPASS $CONFIGURATION  -k yes $@ || failed=`expr $failed + 1`

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

testit "set user password with kerberos ccache" $VALGRIND $samba_tool user setpassword nettestuser --newpassword=$USERPASS $CONFIGURATION  -k yes $@ || failed=`expr $failed + 1`

testit "enable user with kerberos cache" $VALGRIND $samba_enableaccount nettestuser -H ldap://$SERVER -k yes $@ || failed=`expr $failed + 1`

###########################################################
### Test kinit with user credentials
###########################################################

KRB5CCNAME_PATH="$PREFIX/tmpuserccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

rm -f $KRB5CCNAME_PATH

cat > $PREFIX/tmpkinituserpassscript <<EOF
expect Password for
send ${USERPASS}\n
EOF

testit "kinit with user password" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit nettestuser@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

### Change password

NEWUSERPASS="testPaSS@34%"
testit "change user password with 'samba-tool user password' (rpc)" $VALGRIND $samba_tool user password -W$DOMAIN -Unettestuser%$USERPASS $CONFIGURATION -k no --newpassword=$NEWUSERPASS $@ || failed=`expr $failed + 1`

cat > $PREFIX/tmpkinituserpassscript <<EOF
expect Password for
send ${NEWUSERPASS}\n
EOF

testit "kinit with new user password" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit nettestuser@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

$samba_kdestroy

###########################################################
### Test kinit with user credentials in special formats
###########################################################

testit "kinit with new (NT-Principal style) using UPN" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit nettest@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache from NT UPN" 'ls' -k yes || failed=`expr $failed + 1`

$samba_kdestroy

testit "kinit with new (enterprise style) using UPN" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit -E nettest@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache from enterprise UPN" 'ls' -k yes || failed=`expr $failed + 1`

$samba_kdestroy

###########################################################
### Test kinit with user credentials and changed realm
###########################################################

cat > $PREFIX/tmpldbmodify <<EOF
dn: cn=nettestuser,cn=users,$BASEDN
changetype: modify
replace: userPrincipalName
userPrincipalName: nettest@$REALM.org
EOF

testit "modify userPrincipalName to be a different domain" $VALGRIND $ldbmodify $ADMIN_LDBMODIFY_CONFIG $PREFIX/tmpldbmodify $PREFIX/tmpldbmodify -k yes $@ || failed=`expr $failed + 1`

testit "kinit with new (enterprise style) using UPN" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit -E nettest@$REALM.org   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache from enterprise UPN" 'ls' -k yes || failed=`expr $failed + 1`

$samba_kdestroy

###########################################################
### Test password change with kpasswd
###########################################################

testit "kinit with user password" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit nettestuser@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

USERPASS=$NEWUSERPASS
NEWUSERPASS=testPaSS@56%

cat > $PREFIX/tmpkpasswdscript <<EOF
expect Password for
password ${USERPASS}\n
expect Enter new password
send ${NEWUSERPASS}\n
expect Enter it again
send ${NEWUSERPASS}\n
expect Password changed
EOF

testit "change user password with kpasswd" $samba_texpect $PREFIX/tmpkpasswdscript $samba_kpasswd nettestuser@$REALM || failed=`expr $failed + 1`

$samba_kdestroy

USERPASS=$NEWUSERPASS
cat > $PREFIX/tmpkinituserpassscript <<EOF
expect Password for
send ${USERPASS}\n
EOF

testit "kinit with user password" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit nettestuser@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

$samba_kdestroy

###########################################################
### TODO Test set password with kpasswd
###########################################################

# This is not implemented in kpasswd

###########################################################
### Test password expiry
###########################################################

cat > $PREFIX/tmpldbmodify <<EOF
dn: cn=nettestuser,cn=users,$BASEDN
changetype: modify
replace: pwdLastSet
pwdLastSet: 0
EOF

USERPASS=$NEWUSERPASS
NEWUSERPASS=testPaSS@911%

testit "modify pwdLastSet" $VALGRIND $ldbmodify $ADMIN_LDBMODIFY_CONFIG $PREFIX/tmpldbmodify $PREFIX/tmpldbmodify -k yes $@ || failed=`expr $failed + 1`

cat > $PREFIX/tmpkinituserpassscript <<EOF
expect Password for
send ${USERPASS}\n
expect Password expired.  You must change it now.
expect Enter new password
send ${NEWUSERPASS}\n
expect Enter it again
send ${NEWUSERPASS}\n
EOF

testit "kinit (MIT) with user password for expired password" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit nettestuser@$REALM || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

USERPASS=$NEWUSERPASS
cat > $PREFIX/tmpkinituserpassscript <<EOF
expect Password for
send ${USERPASS}\n
EOF

testit "kinit with user password" $samba_texpect $PREFIX/tmpkinituserpassscript $samba_kinit nettestuser@$REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

###########################################################
### Test login with lowercase realm
###########################################################

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

rm -rf $KRB5CCNAME_PATH

lowerrealm=$(echo $REALM | tr '[A-Z]' '[a-z]')
test_smbclient "Test login with user kerberos lowercase realm" 'ls' -k yes -Unettestuser@$lowerrealm%$NEWUSERPASS || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos lowercase realm 2" 'ls' -k yes -Unettestuser@$REALM%$NEWUSERPASS --realm=$lowerrealm || failed=`expr $failed + 1`

testit "del user with kerberos ccache" $VALGRIND $samba_tool user delete nettestuser $CONFIGURATION -k yes $@ || failed=`expr $failed + 1`

###########################################################
### Test login with machine account
###########################################################

rm -f $KRB5CCNAME_PATH
testit "kinit with machineaccountccache script" $machineaccountccache $CONFIGURATION $KRB5CCNAME || failed=`expr $failed + 1`
test_smbclient "Test machine account login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

testit "reset password policies" $VALGRIND $samba_tool domain passwordsettings $ADMIN_LDBMODIFY_CONFIG set --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=default --max-pwd-age=default || failed=`expr $failed + 1`

### Cleanup

$samba_kdestroy

rm -f $KRB5CCNAME_PATH
rm -f $PREFIX/tmpkinituserpassscript
rm -f $PREFIX/tmpkinitscript
rm -f $PREFIX/tmpkpasswdscript
exit $failed
