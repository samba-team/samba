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
DATADIR=../testdata

PATH=bin:$PATH
export PATH

testit "base.js" $SCRIPTDIR/base.js $CONFIGURATION || failed=`expr $failed + 1`

for f in samr.js echo.js; do
    testit "$f" $SCRIPTDIR/$f $CONFIGURATION ncalrpc: -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`
done

#testit "ejsnet.js" $SCRIPTDIR/ejsnet.js $CONFIGURATION -U$USERNAME%$PASSWORD $DOMAIN ejstestuser || failed=`expr $failed + 1`

testit "ldb.js" $SCRIPTDIR/ldb.js `pwd` $CONFIGURATION || failed=`expr $failed + 1`

testit "samba3sam.js" $SCRIPTDIR/samba3sam.js $CONFIGURATION `pwd` $DATADIR/samba3/ || failed=`expr $failed + 1`

testit "winreg" scripting/bin/winreg $CONFIGURATION ncalrpc: 'HKLM' -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`

testok $0 $failed
