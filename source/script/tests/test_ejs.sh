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

testit "base.js" $SCRIPTDIR/base.js $CONFIGURATION

testit "samr.js" "$SCRIPTDIR/samr.js" $CONFIGURATION ncalrpc: -U$USERNAME%$PASSWORD
testit "echo.js" "$SCRIPTDIR/echo.js" $CONFIGURATION ncalrpc: -U$USERNAME%$PASSWORD

testit "ejsnet.js" $SCRIPTDIR/ejsnet.js $CONFIGURATION -U$USERNAME%$PASSWORD $DOMAIN ejstestuser

testit "ldb.js" $SCRIPTDIR/ldb.js `pwd` $CONFIGURATION

testit "samba3sam.js" $SCRIPTDIR/samba3sam.js $CONFIGURATION `pwd` $DATADIR/samba3/

testit "winreg" scripting/bin/winreg $CONFIGURATION ncalrpc: 'HKLM' -U$USERNAME%$PASSWORD

testok $0 $failed
