#!/bin/sh
# Blackbox tests for kinit and trust validation
# Copyright (c) 2015 Stefan Metzmacher <metze@samba.org>
# Copyright (c) 2016 Andreas Schneider <asn@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_kinit_trusts.sh SERVER USERNAME PASSWORD REALM DOMAIN TRUST_USERNAME TRUST_PASSWORD TRUST_REALM TRUST_DOMAIN PREFIX TYPE
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
shift 5
TRUST_SERVER=$1
TRUST_USERNAME=$2
TRUST_PASSWORD=$3
TRUST_REALM=$4
TRUST_DOMAIN=$5
shift 5
PREFIX=$1
TYPE=$2
shift 2

failed=0

samba_bindir="$BINDIR"
samba_srcdir="$SRCDIR/source4"
samba_kinit=kinit
samba_kdestroy=kdestroy
samba_kpasswd=kpasswd

samba_tool="$samba_bindir/samba-tool"
samba_texpect="$samba_bindir/texpect"

smbclient="$samba_bindir/smbclient"
wbinfo="$samba_bindir/wbinfo"
rpcclient="$samba_bindir/rpcclient"

SMBCLIENT_UNC="//$SERVER.$REALM/tmp"

. `dirname $0`/subunit.sh

test_smbclient() {
	name="$1"
	cmd="$2"
	shift
	shift
	echo "test: $name"
	$VALGRIND $smbclient $CONFIGURATION $SMBCLIENT_UNC -c "$cmd" $@
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

KRB5CCNAME_PATH="$PREFIX/test_kinit_trusts_ccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -rf $KRB5CCNAME_PATH

cat > $PREFIX/tmpkinitscript <<EOF
expect Password for
send ${TRUST_PASSWORD}\n
EOF

###########################################################
### Test incoming trust direction
###########################################################

testit "kinit with password" $samba_texpect $PREFIX/tmpkinitscript $samba_kinit $TRUST_USERNAME@$TRUST_REALM || failed=`expr $failed + 1`
test_smbclient "Test login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`
$samba_kdestroy

smbclient="$samba_bindir/smbclient4"

testit "kinit with password" $samba_texpect $PREFIX/tmpkinitscript $samba_kinit $TRUST_USERNAME@$TRUST_REALM || failed=`expr $failed + 1`
test_smbclient "Test login with kerberos ccache (smbclient4)" 'ls' -k yes || failed=`expr $failed + 1`
$samba_kdestroy

smbclient="$samba_bindir/smbclient"

testit "kinit with password (enterprise)" $samba_texpect $PREFIX/tmpkinitscript $samba_kinit -E $TRUST_USERNAME@$TRUST_REALM || failed=`expr $failed + 1`
test_smbclient "Test login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

$samba_kdestroy

if test x"${TYPE}" = x"forest" ;then
    testit "kinit with password (enterprise UPN)" $samba_texpect $PREFIX/tmpkinitscript $samba_kinit -E testdenied_upn@${TRUST_REALM}.upn || failed=`expr $failed + 1`
    test_smbclient "Test login with user kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`
fi

$samba_kdestroy

testit "kinit with password (enterprise)" $samba_texpect $PREFIX/tmpkinitscript $samba_kinit -E $TRUST_USERNAME@$TRUST_REALM || failed=`expr $failed + 1`
test_smbclient "Test login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

testit "kinit renew ticket" $samba_kinit -R
test_smbclient "Test login with kerberos ccache" 'ls' -k yes || failed=`expr $failed + 1`

testit "check time with kerberos ccache" $VALGRIND $samba_tool time $SERVER.$REALM $CONFIGURATION -k yes $@ || failed=`expr $failed + 1`

$samba_kdestroy

lowerrealm=$(echo $TRUST_REALM | tr '[A-Z]' '[a-z]')
test_smbclient "Test login with user kerberos lowercase realm" 'ls' -k yes -d5 -U$TRUST_USERNAME@$lowerrealm%$TRUST_PASSWORD || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos lowercase realm 2" 'ls' -k yes -U$TRUST_USERNAME@$TRUST_REALM%$TRUST_PASSWORD --realm=$lowerrealm || failed=`expr $failed + 1`

###########################################################
### Test outgoing trust direction
###########################################################

SMBCLIENT_UNC="//$TRUST_SERVER.$TRUST_REALM/tmp"
test_smbclient "Test user login with the first outgoing secret" 'ls' -k yes -U$USERNAME@$REALM%$PASSWORD || failed=`expr $failed + 1`

testit_expect_failure "setpassword should not work" $VALGRIND $samba_tool user setpassword "${TRUST_DOMAIN}\$" --random-password || failed=`expr $failed + 1`

testit "wbinfo ping dc" $VALGRIND $wbinfo --ping-dc --domain=$TRUST_DOMAIN || failed=`expr $failed + 1`
testit "wbinfo change outgoing trust pw" $VALGRIND $wbinfo --change-secret --domain=$TRUST_DOMAIN || failed=`expr $failed + 1`
testit "wbinfo check outgoing trust pw" $VALGRIND $wbinfo --check-secret --domain=$TRUST_DOMAIN || failed=`expr $failed + 1`

test_smbclient "Test user login with the changed outgoing secret" 'ls' -k yes -U$USERNAME@$REALM%$PASSWORD || failed=`expr $failed + 1`

### Cleanup

$samba_kdestroy

rm -f $KRB5CCNAME_PATH
rm -f $PREFIX/tmpkinituserpassscript
rm -f $PREFIX/tmpkinitscript

exit $failed
