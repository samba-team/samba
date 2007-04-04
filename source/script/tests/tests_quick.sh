#!/bin/sh
TORTURE_QUICK="yes"
export TORTURE_QUICK

$SRCDIR/script/tests/test_ejs.sh $DOMAIN $USERNAME $PASSWORD $CONFIGURATION
$SRCDIR/script/tests/test_ldap.sh $SERVER $USERNAME $PASSWORD
$SRCDIR/script/tests/test_nbt.sh $SERVER $USERNAME $PASSWORD
$SRCDIR/script/tests/test_quick.sh //$SERVER/cifs $USERNAME $PASSWORD ""
$SRCDIR/script/tests/test_rpc_quick.sh $SERVER $USERNAME $PASSWORD $DOMAIN
