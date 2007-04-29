#!/bin/sh
TORTURE_QUICK="yes"
export TORTURE_QUICK

$SRCDIR/selftest/test_ejs.sh $CONFIGURATION
$SRCDIR/selftest/test_ldap.sh
$SRCDIR/selftest/test_nbt.sh
$SRCDIR/selftest/test_quick.sh
$SRCDIR/selftest/test_rpc_quick.sh
