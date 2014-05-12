#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME REALM DOMAIN PREFIX SMBCLIENT
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
REALM=$3
DOMAIN=$4
PREFIX=$5
ENCTYPE=$6
PROVDIR=$7
smbclient=$8
shift 8
failed=0

samba4bindir="$BINDIR"
samba4srcdir="$SRCDIR/source4"

samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=bin/samba4kinit
fi


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

test_drs() {
	function="$1"
	name="$2"
	shift
	shift
	echo "test: $name"
	echo $VALGRIND $samba4bindir/samba-tool drs $function $SERVER -k yes $@
	$VALGRIND $samba4bindir/samba-tool drs $function $SERVER -k yes $@
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
rm -f $KRB5CCNAME
testit "kinit with keytab" $samba4kinit $enctype -t $PROVDIR/private/secrets.keytab --use-keytab $USERNAME   || failed=`expr $failed + 1`

#This is important because it puts the ticket for the old KVNO and password into a local ccache
test_smbclient "Test login with kerberos ccache before password change" 'ls' -k yes || failed=`expr $failed + 1`

#check that drs bind works before we change the password (prime the ccache)
test_drs bind "Test drs bind with with kerberos ccache" || failed=`expr $failed + 1`

#check that drs options works before we change the password (prime the ccache)
test_drs options "Test drs options with with kerberos ccache" || failed=`expr $failed + 1`

testit "change dc password" $samba4srcdir/scripting/devel/chgtdcpass -s $PROVDIR/etc/smb.conf || failed=`expr $failed + 1`

#This is important because it shows that the old ticket remains valid (as it must) for incoming connections after the DC password is changed
test_smbclient "Test login with kerberos ccache after password change" 'ls' -k yes || failed=`expr $failed + 1`

#check that drs bind works after we change the password
test_drs bind "Test drs bind with new password" || failed=`expr $failed + 1`

#check that drs options works after we change the password
test_drs options "Test drs options with new password" || failed=`expr $failed + 1`

testit "change dc password (2nd time)" $samba4srcdir/scripting/devel/chgtdcpass -s $PROVDIR/etc/smb.conf || failed=`expr $failed + 1`

#This is important because it shows that the old ticket remains valid (as it must) for incoming connections after the DC pass
test_smbclient "Test login with kerberos ccache after 2nd password change" 'ls' -k yes || failed=`expr $failed + 1`

#check that drs bind works after we change the password a 2nd time
test_drs bind "Test drs bind after 2nd password change" || failed=`expr $failed + 1`

#check that drs options works after we change the password a 2nd time
test_drs options "Test drs options after 2nd password change" || failed=`expr $failed + 1`

#This confirms that the DC password is valid for a kinit too
testit "kinit with keytab" $samba4kinit $enctype -t $PROVDIR/private/secrets.keytab --use-keytab $USERNAME   || failed=`expr $failed + 1`
test_smbclient "Test login with kerberos ccache with fresh kinit" 'ls' -k yes || failed=`expr $failed + 1`
rm -f $KRB5CCNAME

rm -f $PREFIX/tmpccache tmpccfile tmppassfile tmpuserpassfile tmpuserccache tmpkpasswdscript
exit $failed
