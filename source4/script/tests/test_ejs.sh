#!/bin/sh
# test some simple EJS operations

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_ejs.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
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

