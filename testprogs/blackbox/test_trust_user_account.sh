#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_trust_user_account.sh PREFIX OUR_REALM OUR_FLAT REMOTE_REALM REMOTE_FLAT
EOF
exit 1;
fi

PREFIX="$1"
OUR_REALM="$2"
OUR_FLAT="$3"
REMOTE_REALM="$4"
REMOTE_FLAT="$5"
shift 5

. `dirname $0`/subunit.sh


samba_tool="$BINDIR/samba-tool"
samba4bindir="$BINDIR"
samba4srcdir="$SRCDIR/source4"
samba4kinit="kinit -k"
if test -x $BINDIR/samba4kinit; then
	samba4kinit="$BINDIR/samba4kinit --use-keytab"
fi

KEYTAB="$PREFIX/tmptda.keytab"

KRB5_TRACE=/dev/stderr
export KRB5_TRACE

testit "retrieve keytab for TDA of $REMOTE_REALM" $PYTHON $samba_tool domain exportkeytab $KEYTAB $CONFIGURATION --principal "$REMOTE_FLAT\$@$OUR_REALM" || failed=`expr $failed + 1`

KRB5CCNAME="$PREFIX/tmptda.ccache"
export KRB5CCNAME

rm -f $KRB5CCNAME

EXPECTED_SALT="${OUR_REALM}krbtgt${REMOTE_FLAT}"
#
# Note the \$ is for the end of line in grep
#
# There must be no trailing '$' in the SALT string itself,
# it's removed from the sAMAccountName value (which includes the trailing '$')
# before construting the salt!
#
# Otherwise this would be:
# "^virtualKerberosSalt: ${EXPECTED_SALT}\\\$\$"
#
EXPECTED_GREP="^virtualKerberosSalt: ${EXPECTED_SALT}\$"
testit_grep "get virtualKerberosSalt for TDA of $REMOTE_FLAT\$" "$EXPECTED_GREP" $PYTHON $samba_tool user getpassword "$REMOTE_FLAT\$" $CONFIGURATION --attributes=virtualKerberosSalt || failed=`expr $failed + 1`

testit "kinit with keytab for TDA of $REMOTE_REALM" $samba4kinit -t $KEYTAB "$REMOTE_FLAT\$@$OUR_REALM" || failed=`expr $failed + 1`

rm -f $KRB5CCNAME $KEYTAB

exit $failed
