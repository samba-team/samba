#!/bin/sh
 $SRCDIR/script/tests/test_smbclient.sh $SERVER $USERNAME $PASSWORD $DOMAIN $PREFIX || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_cifsdd.sh $SERVER $USERNAME $PASSWORD $DOMAIN || totalfailed=`expr $totalfailed + $?`
