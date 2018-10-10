#!/bin/sh
# Copyright (C) 2015 Stefan Metzmacher <metze@samba.org>

if [ $# -lt 13 ]; then
cat <<EOF
Usage: test_kinit_trusts.sh SERVER USERNAME PASSWORD REALM DOMAIN TRUST_USERNAME TRUST_PASSWORD TRUST_REALM TRUST_DOMAIN PREFIX TYPE ENCTYPE
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
ENCTYPE=$3
shift 3
failed=0

samba4bindir="$BINDIR"
samba4kinit=kinit
if test -x $samba4bindir/samba4kinit; then
	samba4kinit=$samba4bindir/samba4kinit
fi

smbclient="$samba4bindir/smbclient"
wbinfo="$samba4bindir/wbinfo"
rpcclient="$samba4bindir/rpcclient"
samba_tool="$samba4bindir/samba-tool"

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

unc="//$SERVER.$REALM/tmp"

enctype="-e $ENCTYPE"

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -rf $KRB5CCNAME_PATH

echo $TRUST_PASSWORD > $PREFIX/tmppassfile
testit "kinit with password" $samba4kinit $enctype --password-file=$PREFIX/tmppassfile --request-pac $TRUST_USERNAME@$TRUST_REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`
rm -rf $KRB5CCNAME_PATH

# Test with smbclient4
smbclient="$samba4bindir/smbclient4"
testit "kinit with password" $samba4kinit $enctype --password-file=$PREFIX/tmppassfile --request-pac $TRUST_USERNAME@$TRUST_REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache (smbclient4)" 'ls' "$unc" -k yes || failed=`expr $failed + 1`
rm -rf $KRB5CCNAME_PATH

testit "kinit with password (enterprise style)" $samba4kinit $enctype --enterprise --password-file=$PREFIX/tmppassfile --request-pac $TRUST_USERNAME@$TRUST_REALM   || failed=`expr $failed + 1`
smbclient="$samba4bindir/smbclient"
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

if test x"${TYPE}" = x"forest" ;then
	testit "kinit with password (upn enterprise style)" $samba4kinit $enctype --enterprise --password-file=$PREFIX/tmppassfile --request-pac testdenied_upn@${TRUST_REALM}.upn   || failed=`expr $failed + 1`
	test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`
fi

testit "kinit with password (windows style)" $samba4kinit $enctype  --renewable --windows --password-file=$PREFIX/tmppassfile --request-pac $TRUST_USERNAME@$TRUST_REALM   || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

testit "kinit renew ticket" $samba4kinit $enctype --request-pac -R

test_smbclient "Test login with kerberos ccache" 'ls' "$unc" -k yes || failed=`expr $failed + 1`

testit "check time with kerberos ccache" $VALGRIND $PYTHON $samba_tool time $SERVER.$REALM $CONFIGURATION -k yes $@ || failed=`expr $failed + 1`

lowerrealm=$(echo $TRUST_REALM | tr '[A-Z]' '[a-z]')
test_smbclient "Test login with user kerberos lowercase realm" 'ls' "$unc" -k yes -U$TRUST_USERNAME@$lowerrealm%$TRUST_PASSWORD || failed=`expr $failed + 1`
test_smbclient "Test login with user kerberos lowercase realm 2" 'ls' "$unc" -k yes -U$TRUST_USERNAME@$TRUST_REALM%$TRUST_PASSWORD --realm=$lowerrealm || failed=`expr $failed + 1`

# Test the outgoing direction
SMBCLIENT_UNC="//$TRUST_SERVER.$TRUST_REALM/tmp"
test_smbclient "Test user login with the first outgoing secret" 'ls' "$unc" -k yes -U$USERNAME@$REALM%$PASSWORD || failed=`expr $failed + 1`

testit_expect_failure "setpassword should not work" $VALGRIND $PYTHON $samba_tool user setpassword "${TRUST_DOMAIN}\$" --random-password || failed=`expr $failed + 1`

testit "wbinfo ping dc" $VALGRIND $wbinfo --ping-dc --domain=$TRUST_DOMAIN || failed=`expr $failed + 1`
testit "wbinfo change outgoing trust pw" $VALGRIND $wbinfo --change-secret --domain=$TRUST_DOMAIN || failed=`expr $failed + 1`
testit "wbinfo check outgoing trust pw" $VALGRIND $wbinfo --check-secret --domain=$TRUST_DOMAIN || failed=`expr $failed + 1`

test_smbclient "Test user login with the changed outgoing secret" 'ls' "$unc" -k yes -U$USERNAME@$REALM%$PASSWORD || failed=`expr $failed + 1`

rm -f $PREFIX/tmpccache tmpccfile tmppassfile tmpuserpassfile tmpuserccache
exit $failed
