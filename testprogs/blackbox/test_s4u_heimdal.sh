#!/bin/sh

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_kinit.sh SERVER USERNAME PASSWORD REALM DOMAIN PREFIX
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


samba_tool="$VALGRIND $PYTHON $BINDIR/samba-tool"

samba4kinit=kinit
if test -x $BINDIR/samba4kinit; then
	samba4kinit=$BINDIR/samba4kinit
fi

samba4kgetcred=kgetcred
if test -x $BINDIR/samba4kgetcred; then
	samba4kgetcred=$BINDIR/samba4kgetcred
fi

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

ocache="$PREFIX/tmpoutcache"
KRB5CCNAME_PATH="$PREFIX/tmpccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -rf $KRB5CCNAME_PATH

princ=test_impersonate_princ
impersonator=test_impersonator
target="CIFS/$SERVER.$REALM"


testit "add impersonator principal" $samba_tool user add $impersonator $PASSWORD || failed=`expr $failed + 1`
testit "become a service" $samba_tool spn add "HOST/$impersonator" $impersonator || failed=`expr $failed + 1`

testit "set TrustedToAuthForDelegation" $samba_tool delegation for-any-protocol $impersonator on || failed=`expr $failed + 1`
testit "add msDS-AllowedToDelegateTo" $samba_tool delegation add-service $impersonator $target || failed=`expr $failed + 1`

testit "add a new principal" $samba_tool user add $princ --random-password || failed=`expr $failed + 1`
testit "set not-delegated flag" $samba_tool user sensitive $princ on || failed=`expr $failed + 1`


echo $PASSWORD > $PREFIX/tmppassfile
testit "kinit with password" $samba4kinit -f --password-file=$PREFIX/tmppassfile $impersonator || failed=`expr $failed + 1`

testit "test S4U2Self with normal user" $samba4kgetcred --out-cache=$ocache --forwardable --impersonate=${USERNAME} $impersonator || failed=`expr $failed + 1`
testit "test S4U2Proxy with normal user" $samba4kgetcred --out-cache=$ocache --delegation-credential-cache=${ocache} $target || failed=`expr $failed + 1`

testit "test S4U2Self with sensitive user" $samba4kgetcred --out-cache=$ocache --forwardable --impersonate=$princ $impersonator || failed=`expr $failed + 1`
testit_expect_failure "test S4U2Proxy with sensitive user" $samba4kgetcred --out-cache=$ocache --delegation-credential-cache=${ocache} $target || failed=`expr $failed + 1`

rm -f $ocache
testit "unset not-delegated flag" $samba_tool user sensitive $princ off || failed=`expr $failed + 1`

testit "test S4U2Self after unsetting ND flag" $samba4kgetcred --out-cache=$ocache --forwardable --impersonate=$princ $impersonator || failed=`expr $failed + 1`
testit "test S4U2Proxy after unsetting ND flag" $samba4kgetcred --out-cache=$ocache --delegation-credential-cache=${ocache} $target || failed=`expr $failed + 1`


rm -f $ocache $PREFIX/tmpccache tmppassfile
exit $failed
