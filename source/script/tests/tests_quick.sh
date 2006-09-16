#!/bin/sh
TORTURE_OPTIONS="$TORTURE_OPTIONS --option=torture:quick=yes"
export TORTURE_OPTIONS
TORTURE_QUICK="yes"
export TORTURE_QUICK

$SRCDIR/script/tests/test_ejs.sh $DOMAIN $USERNAME $PASSWORD || totalfailed=`expr $totalfailed + $?`
$SRCDIR/script/tests/test_ldap.sh $SERVER $USERNAME $PASSWORD || totalfailed=`expr $totalfailed + $?`
$SRCDIR/script/tests/test_nbt.sh $SERVER || totalfailed=`expr $totalfailed + $?`
$SRCDIR/script/tests/test_quick.sh //$SERVER/cifs $USERNAME $PASSWORD "" || totalfailed=`expr $totalfailed + $?`
$SRCDIR/script/tests/test_rpc_quick.sh $SERVER $USERNAME $PASSWORD $DOMAIN || totalfailed=`expr $totalfailed + $?`
#$SRCDIR/script/tests/test_cifsposix.sh //$SERVER/cifsposixtestshare $USERNAME $PASSWORD "" || totalfailed=`expr $totalfailed + $?`
