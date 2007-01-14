#!/bin/sh
 $SRCDIR/script/tests/test_ejs.sh $DOMAIN $USERNAME $PASSWORD || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_ldap.sh $SERVER $USERNAME $PASSWORD || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_nbt.sh $SERVER || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_quick.sh //$SERVER/cifs $USERNAME $PASSWORD "" || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_rpc.sh $SERVER $USERNAME $PASSWORD $DOMAIN || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_net.sh $SERVER $USERNAME $PASSWORD $DOMAIN || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_session_key.sh $SERVER $USERNAME $PASSWORD $DOMAIN $NETBIOSNAME || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_binding_string.sh $SERVER $USERNAME $PASSWORD $DOMAIN || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_echo.sh $SERVER $USERNAME $PASSWORD $DOMAIN || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_posix.sh //$SERVER/tmp $USERNAME $PASSWORD "" || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_local.sh || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_pidl.sh || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_blackbox.sh $SERVER $USERNAME $PASSWORD $DOMAIN $PREFIX || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_cifsdd.sh $SERVER $USERNAME $PASSWORD $DOMAIN || totalfailed=`expr $totalfailed + $?`
 $SRCDIR/script/tests/test_simple.sh //$SERVER/simple $USERNAME $PASSWORD "" || totalfailed=`expr $totalfailed + $?`
