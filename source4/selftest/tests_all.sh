#!/bin/sh
 $SRCDIR/selftest/test_ejs.sh $CONFIGURATION
 $SRCDIR/selftest/test_ldap.sh 
 $SRCDIR/selftest/test_nbt.sh "dc"
 $SRCDIR/selftest/test_rpc.sh
 $SRCDIR/selftest/test_net.sh
 $SRCDIR/selftest/test_session_key.sh
 $SRCDIR/selftest/test_binding_string.sh
 $SRCDIR/selftest/test_echo.sh
 $SRCDIR/selftest/test_posix.sh
 $SRCDIR/selftest/test_cifs.sh
 $SRCDIR/selftest/test_local.sh
 $SRCDIR/selftest/test_pidl.sh
 $SRCDIR/selftest/test_blackbox.sh $PREFIX
 $SRCDIR/selftest/test_simple.sh
 $SRCDIR/selftest/test_s3upgrade.sh $PREFIX/upgrade
 $SRCDIR/selftest/test_member.sh
 $SRCDIR/selftest/test_nbt.sh "member"
