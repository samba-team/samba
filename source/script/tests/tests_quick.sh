#!/bin/sh
TORTURE_QUICK="yes"
export TORTURE_QUICK

$SRCDIR/script/tests/test_ejs.sh $CONFIGURATION
$SRCDIR/script/tests/test_ldap.sh
$SRCDIR/script/tests/test_nbt.sh
$SRCDIR/script/tests/test_quick.sh
$SRCDIR/script/tests/test_rpc_quick.sh
