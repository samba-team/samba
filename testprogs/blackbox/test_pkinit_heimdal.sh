#!/bin/sh
# Blackbox tests for kinit and kerberos integration with smbclient etc
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX ENCTYPE SMBCLINET
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
wbinfo="$samba4bindir/wbinfo"
samba4kpasswd=kpasswd
if test -x $BINDIR/samba4kpasswd; then
	samba4passwd=$BINDIR/samba4kpasswd
fi

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

KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -f $KRB5CCNAME_PATH
PASSFILE_PATH="$PREFIX/tmppassfile"
rm -f $PASSFILE_PATH
echo $PASSWORD > $PASSFILE_PATH

USER_PRINCIPAL_NAME=`echo "${USERNAME}@${REALM}" | tr A-Z a-z`
PKUSER="--pk-user=FILE:$PREFIX/pkinit/USER-${USER_PRINCIPAL_NAME}-cert.pem,$PREFIX/pkinit/USER-${USER_PRINCIPAL_NAME}-private-key.pem"

# STEP1:
# Now we set the UF_SMARTCARD_REQUIRED bit
# This means we have a normal enabled account *without* a known password
testit "STEP1 samba-tool user create $USERNAME --smartcard-required" $PYTHON ${samba_tool} user create $USERNAME --smartcard-required || failed=`expr $failed + 1`

testit_expect_failure "STEP1 kinit with password" $samba4kinit $enctype --password-file=$PASSFILE_PATH --request-pac $USERNAME@$REALM   && failed=`expr $failed + 1`
testit_expect_failure "STEP1 Test login with NTLM" $smbclient "$unc" -c 'ls' -U$USERNAME%$PASSWORD && failed=`expr $failed + 1`
testit_expect_failure "STEP1 Test wbinfo with password" $wbinfo --authenticate=$DOMAIN/$USERNAME%$PASSWORD && failed=`expr $failed + 1`

testit "STEP1 kinit with pkinit (name specified) " $samba4kinit $enctype --request-pac --renewable $PKUSER $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP1 kinit renew ticket (name specified)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP1 Test login with kerberos ccache (name specified)" 'ls' "$unc" -k || failed=`expr $failed + 1`

testit_expect_failure "STEP1 kinit with pkinit (wrong name specified) " $samba4kinit $enctype --request-pac --renewable $PKUSER not$USERNAME@$REALM || failed=`expr $failed + 1`

testit_expect_failure "STEP1 kinit with pkinit (wrong name specified 2) " $samba4kinit $enctype --request-pac --renewable $PKUSER $SERVER@$REALM || failed=`expr $failed + 1`

testit "STEP1 kinit with pkinit (enterprise name specified)" $samba4kinit $enctype --request-pac --renewable $PKUSER --enterprise $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP1 kinit renew ticket (enterprise name specified)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP1 Test login with kerberos ccache (enterprise name specified)" 'ls' "$unc" -k || failed=`expr $failed + 1`

testit_expect_failure "STEP1 kinit with pkinit (wrong enterprise name specified) " $samba4kinit $enctype --request-pac --renewable $PKUSER --enterprise not$USERNAME@$REALM || failed=`expr $failed + 1`

testit_expect_failure "STEP1 kinit with pkinit (wrong enterprise name specified 2) " $samba4kinit $enctype --request-pac --renewable $PKUSER --enterprise $SERVER$@$REALM || failed=`expr $failed + 1`

testit "STEP1 kinit with pkinit (enterprise name in cert)" $samba4kinit $enctype --request-pac --renewable $PKUSER --pk-enterprise || failed=`expr $failed + 1`
testit "STEP1 kinit renew ticket (enterprise name in cert)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP1 Test login with kerberos ccache (enterprise name in cert)" 'ls' "$unc" -k || failed=`expr $failed + 1`

# STEP2:
# We still have UF_SMARTCARD_REQUIRED, but with a known password
testit "STEP2 samba-tool user setpassword $USERNAME --newpassword" $PYTHON ${samba_tool} user setpassword $USERNAME --newpassword=$PASSWORD || failed=`expr $failed + 1`

testit_expect_failure "STEP2 kinit with password" $samba4kinit $enctype --password-file=$PASSFILE_PATH --request-pac $USERNAME@$REALM   && failed=`expr $failed + 1`
test_smbclient "STEP2 Test login with NTLM" 'ls' "$unc" -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`
testit_expect_failure "STEP2 Test wbinfo with password" $wbinfo --authenticate=$DOMAIN/$USERNAME%$PASSWORD && failed=`expr $failed + 1`

testit "STEP2 kinit with pkinit (name specified) " $samba4kinit $enctype --request-pac --renewable $PKUSER $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP2 kinit renew ticket (name specified)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP2 Test login with kerberos ccache (name specified)" 'ls' "$unc" -k || failed=`expr $failed + 1`

testit "STEP2 kinit with pkinit (enterprise name specified)" $samba4kinit $enctype --request-pac --renewable $PKUSER --enterprise $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP2 kinit renew ticket (enterprise name specified)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP2 Test login with kerberos ccache (enterprise name specified)" 'ls' "$unc" -k || failed=`expr $failed + 1`

testit "STEP2 kinit with pkinit (enterprise name in cert)" $samba4kinit $enctype --request-pac --renewable $PKUSER --pk-enterprise || failed=`expr $failed + 1`
testit "STEP2 kinit renew ticket (enterprise name in cert)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP2 Test login with kerberos ccache (enterprise name in cert)" 'ls' "$unc" -k || failed=`expr $failed + 1`

# STEP3:
# The account is a normal account without the UF_SMARTCARD_REQUIRED bit set
testit "STEP3 samba-tool user setpassword $USERNAME --smartcard-required" $PYTHON ${samba_tool} user setpassword $USERNAME --newpassword=$PASSWORD --clear-smartcard-required  || failed=`expr $failed + 1`

testit "STEP3 kinit with password" $samba4kinit $enctype --password-file=$PASSFILE_PATH --request-pac $USERNAME@$REALM   || failed=`expr $failed + 1`
test_smbclient "STEP3 Test login with user kerberos ccache" 'ls' "$unc" -k || failed=`expr $failed + 1`
test_smbclient "STEP3 Test login with NTLM" 'ls' "$unc" -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`
testit "STEP3 Test wbinfo with password" $wbinfo --authenticate=$DOMAIN/$USERNAME%$PASSWORD || failed=`expr $failed + 1`

testit "STEP3 kinit with pkinit (name specified) " $samba4kinit $enctype --request-pac --renewable $PKUSER $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP3 kinit renew ticket (name specified)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP3 Test login with kerberos ccache (name specified)" 'ls' "$unc" -k || failed=`expr $failed + 1`

testit "STEP3 kinit with pkinit (enterprise name specified)" $samba4kinit $enctype --request-pac --renewable $PKUSER --enterprise $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP3 kinit renew ticket (enterprise name specified)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP3 Test login with kerberos ccache (enterprise name specified)" 'ls' "$unc" -k || failed=`expr $failed + 1`

testit "STEP3 kinit with pkinit (enterprise name in cert)" $samba4kinit $enctype --request-pac --renewable $PKUSER --pk-enterprise || failed=`expr $failed + 1`
testit "STEP3 kinit renew ticket (enterprise name in cert)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP3 Test login with kerberos ccache (enterprise name in cert)" 'ls' "$unc" -k || failed=`expr $failed + 1`

# STEP4:
# Now we set the UF_SMARTCARD_REQUIRED bit
# This means we have a normal enabled account *without* a known password
testit "STEP4 samba-tool user setpassword $USERNAME --smartcard-required" $PYTHON ${samba_tool} user setpassword $USERNAME --smartcard-required || failed=`expr $failed + 1`

testit_expect_failure "STEP4 kinit with password" $samba4kinit $enctype --password-file=$PASSFILE_PATH --request-pac $USERNAME@$REALM   && failed=`expr $failed + 1`
testit_expect_failure "STEP4 Test login with NTLM" $smbclient "$unc" -c 'ls' -U$USERNAME%$PASSWORD && failed=`expr $failed + 1`
testit_expect_failure "STEP4 Test wbinfo with password" $wbinfo --authenticate=$DOMAIN/$USERNAME%$PASSWORD && failed=`expr $failed + 1`

testit "STEP4 kinit with pkinit (name specified) " $samba4kinit $enctype --request-pac --renewable $PKUSER $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP4 kinit renew ticket (name specified)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP4 Test login with kerberos ccache (name specified)" 'ls' "$unc" -k || failed=`expr $failed + 1`

testit "STEP4 kinit with pkinit (enterprise name specified)" $samba4kinit $enctype --request-pac --renewable $PKUSER --enterprise $USERNAME@$REALM || failed=`expr $failed + 1`
testit "STEP4 kinit renew ticket (enterprise name specified)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP4 Test login with kerberos ccache (enterprise name specified)" 'ls' "$unc" -k || failed=`expr $failed + 1`

testit "STEP4 kinit with pkinit (enterprise name in cert)" $samba4kinit $enctype --request-pac --renewable $PKUSER --pk-enterprise || failed=`expr $failed + 1`
testit "STEP4 kinit renew ticket (enterprise name in cert)" $samba4kinit --request-pac -R  || failed=`expr $failed + 1`
test_smbclient "STEP4 Test login with kerberos ccache (enterprise name in cert)" 'ls' "$unc" -k || failed=`expr $failed + 1`

# STEP5:
# disable the account
testit "STEP5 samba-tool user disable $USERNAME" $PYTHON ${samba_tool} user disable $USERNAME || failed=`expr $failed + 1`

testit_expect_failure "STEP5 kinit with password" $samba4kinit $enctype --password-file=$PASSFILE_PATH --request-pac $USERNAME@$REALM   && failed=`expr $failed + 1`
testit_expect_failure "STEP5 Test login with NTLM" $smbclient "$unc" -c 'ls' -U$USERNAME%$PASSWORD && failed=`expr $failed + 1`
testit_expect_failure "STEP5 Test wbinfo with password" $wbinfo --authenticate=$DOMAIN/$USERNAME%$PASSWORD && failed=`expr $failed + 1`

testit_expect_failure "STEP5 kinit with pkinit (name specified) " $samba4kinit $enctype --request-pac --renewable $PKUSER $USERNAME@$REALM && failed=`expr $failed + 1`
testit_expect_failure "STEP5 kinit with pkinit (enterprise name specified)" $samba4kinit $enctype --request-pac --renewable $PKUSER --enterprise $USERNAME@$REALM && failed=`expr $failed + 1`
testit_expect_failure "STEP5 kinit with pkinit (enterprise name in cert)" $samba4kinit $enctype --request-pac --renewable $PKUSER --pk-enterprise && failed=`expr $failed + 1`

# STEP6:
# cleanup
testit "STEP6 samba-tool user delete $USERNAME " $PYTHON ${samba_tool} user delete $USERNAME || failed=`expr $failed + 2`

rm -f $PASSFILE_PATH
rm -f $KRB5CCNAME_PATH
exit $failed
