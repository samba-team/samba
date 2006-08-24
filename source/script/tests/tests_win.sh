#!/bin/sh

 if [ `whoami` != "root" ]; then
       echo "Windows tests will not run without root privilages."
       exit 1
 fi

 if [ "$DO_SOCKET_WRAPPER" = SOCKET_WRAPPER ]; then
       echo "Windows tests will not run with socket wrapper enabled."
       exit 1
 fi

 WINTEST_CONFFILE="$SRCDIR/script/tests/win/test_win.conf"
 if [ ! -r $WINTEST_CONFFILE ]; then
       echo "$WINTEST_CONFFILE could not be read."
       exit 1
 fi

 export WINTEST_DIR=$SRCDIR/script/tests/win
 export TMPDIR=$TMPDIR
 export NETBIOSNAME=$NETBIOSNAME

 . $WINTEST_CONFFILE

 $SRCDIR/script/tests/test_win.sh
 status=$?

 echo "$0 exits with status $status"
 exit $status
