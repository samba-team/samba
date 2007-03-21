#!/bin/sh
# test some simple EJS operations

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_ejs.sh DOMAIN USERNAME PASSWORD [OPTIONS]
EOF
exit 1;
fi

DOMAIN="$1"
USERNAME="$2"
PASSWORD="$3"
shift 3
CONFIGURATION="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

SCRIPTDIR=../testprogs/ejs
DATADIR=../testdata

PATH=bin:$PATH
export PATH

plantest "base.js" rpc "$SCRIPTDIR/base.js" $CONFIGURATION
plantest "samr.js" rpc "$SCRIPTDIR/samr.js" $CONFIGURATION ncalrpc: -U$USERNAME%$PASSWORD
plantest "echo.js" rpc "$SCRIPTDIR/echo.js" $CONFIGURATION ncalrpc: -U$USERNAME%$PASSWORD
plantest "ejsnet.js" rpc "$SCRIPTDIR/ejsnet.js" $CONFIGURATION -U$USERNAME%$PASSWORD $DOMAIN ejstestuser
plantest "ldb.js" none "$SCRIPTDIR/ldb.js" `pwd` $CONFIGURATION
plantest "samba3sam.js" none $SCRIPTDIR/samba3sam.js $CONFIGURATION `pwd` $DATADIR/samba3/
plantest "winreg" rpc scripting/bin/winreg $CONFIGURATION ncalrpc: 'HKLM' -U$USERNAME%$PASSWORD
