#!/bin/sh
# test some simple EJS operations

CONFIGURATION="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

SCRIPTDIR=../testprogs/ejs
DATADIR=../testdata

PATH=bin:$PATH
export PATH

plantest "base.js" dc "$SCRIPTDIR/base.js" $CONFIGURATION
plantest "samr.js" dc "$SCRIPTDIR/samr.js" $CONFIGURATION ncalrpc: -U\$USERNAME%\$PASSWORD
plantest "echo.js" dc "$SCRIPTDIR/echo.js" $CONFIGURATION ncalrpc: -U\$USERNAME%\$PASSWORD
plantest "ejsnet.js" dc "$SCRIPTDIR/ejsnet.js" $CONFIGURATION -U\$USERNAME%\$PASSWORD \$DOMAIN ejstestuser
plantest "ldb.js" none "$SCRIPTDIR/ldb.js" `pwd` $CONFIGURATION
plantest "samba3sam.js" none $SCRIPTDIR/samba3sam.js $CONFIGURATION `pwd` $DATADIR/samba3/
plantest "winreg" dc scripting/bin/winreg $CONFIGURATION ncalrpc: 'HKLM' -U\$USERNAME%\$PASSWORD
