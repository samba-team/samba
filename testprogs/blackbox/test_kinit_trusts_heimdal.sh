#!/bin/sh
# Copyright (C) 2015 Stefan Metzmacher <metze@samba.org>

if [ $# -lt 14 ]; then
	cat <<EOF
Usage: test_kinit_trusts.sh SERVER USERNAME PASSWORD REALM DOMAIN TRUST_USERNAME TRUST_PASSWORD TRUST_REALM TRUST_DOMAIN PREFIX TYPE ENCTYPE CONFIGURATION
EOF
	exit 1
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
ENCTYPE=$3
CONFIGURATION="${4}"
shift 3
failed=0

samba4bindir="$BINDIR"
samba4kinit_binary=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit_binary=$BINDIR/samba4kinit
fi

smbclient="$samba4bindir/smbclient"
wbinfo="$samba4bindir/wbinfo"
rpcclient="$samba4bindir/rpcclient"
samba_tool="$samba4bindir/samba-tool"

. $(dirname $0)/subunit.sh
. $(dirname $0)/common_test_fns.inc

unc="//$SERVER.$REALM/tmp"

enctype="-e $ENCTYPE"

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
samba4kinit="$samba4kinit_binary -c $KRB5CCNAME"
export KRB5CCNAME
rm -rf $KRB5CCNAME_PATH

echo $TRUST_PASSWORD >$PREFIX/tmppassfile
testit "kinit with password" $samba4kinit $enctype --password-file=$PREFIX/tmppassfile --request-pac $TRUST_USERNAME@$TRUST_REALM || failed=$(expr $failed + 1)
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME || failed=$(expr $failed + 1)
rm -rf $KRB5CCNAME_PATH

testit "kinit with password and two minute lifetime" $samba4kinit $enctype --password-file=$PREFIX/tmppassfile --request-pac --server=krbtgt/$REALM@$TRUST_REALM --lifetime=2m $TRUST_USERNAME@$TRUST_REALM || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache and two minute lifetime" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME || failed=`expr $failed + 1`
rm -rf $KRB5CCNAME_PATH

# Test with smbclient4
smbclient="$samba4bindir/smbclient4"
testit "kinit with password" $samba4kinit $enctype --password-file=$PREFIX/tmppassfile --request-pac $TRUST_USERNAME@$TRUST_REALM || failed=$(expr $failed + 1)
test_smbclient "Test login with user kerberos ccache (smbclient4)" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME || failed=$(expr $failed + 1)
rm -rf $KRB5CCNAME_PATH

testit "kinit with password (enterprise style)" $samba4kinit $enctype --enterprise --password-file=$PREFIX/tmppassfile --request-pac $TRUST_USERNAME@$TRUST_REALM || failed=$(expr $failed + 1)
smbclient="$samba4bindir/smbclient"
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME || failed=$(expr $failed + 1)

if test x"${TYPE}" = x"forest"; then
	testit "kinit with password (upn enterprise style)" $samba4kinit $enctype --enterprise --password-file=$PREFIX/tmppassfile --request-pac testdenied_upn@${TRUST_REALM}.upn || failed=$(expr $failed + 1)
	test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME || failed=$(expr $failed + 1)
fi

testit "kinit with password (windows style)" $samba4kinit $enctype --renewable --windows --password-file=$PREFIX/tmppassfile --request-pac $TRUST_USERNAME@$TRUST_REALM || failed=$(expr $failed + 1)
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME || failed=$(expr $failed + 1)

testit "kinit renew ticket" $samba4kinit $enctype --request-pac -R

test_smbclient "Test login with kerberos ccache" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME || failed=$(expr $failed + 1)

testit "check time with kerberos ccache" $VALGRIND $PYTHON $samba_tool time $SERVER.$REALM $CONFIGURATION -k yes "$@" || failed=$(expr $failed + 1)

lowerrealm=$(echo $TRUST_REALM | tr '[A-Z]' '[a-z]')
test_smbclient "Test login with user kerberos lowercase realm" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME -U$TRUST_USERNAME@$lowerrealm%$TRUST_PASSWORD || failed=$(expr $failed + 1)
test_smbclient "Test login with user kerberos lowercase realm 2" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME -U$TRUST_USERNAME@$TRUST_REALM%$TRUST_PASSWORD --realm=$lowerrealm || failed=$(expr $failed + 1)

# Test the outgoing direction
unc="//$TRUST_SERVER.$TRUST_REALM/tmp"
test_smbclient "Test user login with the first outgoing secret" 'ls' "$unc" --use-krb5-ccache=$KRB5CCNAME -U$USERNAME@$REALM%$PASSWORD || failed=$(expr $failed + 1)

testit_expect_failure "setpassword should not work" $VALGRIND $PYTHON $samba_tool user setpassword "${TRUST_DOMAIN}\$" --random-password || failed=$(expr $failed + 1)

testit "wbinfo ping dc" $VALGRIND $wbinfo --ping-dc --domain=$TRUST_DOMAIN || failed=$(expr $failed + 1)
testit "wbinfo change outgoing trust pw" $VALGRIND $wbinfo --change-secret --domain=$TRUST_DOMAIN || failed=$(expr $failed + 1)
testit "wbinfo check outgoing trust pw" $VALGRIND $wbinfo --check-secret --domain=$TRUST_DOMAIN || failed=$(expr $failed + 1)

test_smbclient "Test user login with the changed outgoing secret" 'ls' "$unc" --use-kerberos=required -U$USERNAME@$REALM%$PASSWORD || failed=$(expr $failed + 1)

rm -f $PREFIX/tmpccache $PREFIX/tmppassfile
exit $failed
