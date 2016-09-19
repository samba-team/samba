#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_wbinfo_simple.sh <wbinfo args>
EOF
exit 1;
fi

ADDARGS="$*"

incdir=`dirname $0`/../../testprogs/blackbox
. $incdir/subunit.sh

KRB5CCNAME_PATH="$PREFIX/test_wbinfo_simple_krb5ccname"
rm -f $KRB5CCNAME_PATH

KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

testit "wbinfo" $VALGRIND $BINDIR/wbinfo --krb5ccname="$KRB5CCNAME" $ADDARGS || failed=`expr $failed + 1`

rm -f $KRB5CCNAME_PATH

testok $0 $failed
