#!/bin/sh
# test some simple EJS operations

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_ejs.sh DOMAIN USERNAME PASSWORD
EOF
exit 1;
fi

DOMAIN="$1"
USERNAME="$2"
PASSWORD="$3"

incdir=`dirname $0`
. $incdir/test_functions.sh

SCRIPTDIR=../testprogs/ejs

PATH=bin:$PATH
export PATH

for f in samr.js echo.js ldb.js; do
    testit "$f" $SCRIPTDIR/$f $CONFIGURATION ncalrpc: -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`
done

testit "ejsnet.js" $SCRIPTDIR/ejsnet.js $CONFIGURATION -U$USERNAME%$PASSWORD $DOMAIN ejstestuser || failed=`expr $failed + 1`

testit "winreg" scripting/bin/winreg $CONFIGURATION ncalrpc: 'HKLM' -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`

testok $0 $failed
