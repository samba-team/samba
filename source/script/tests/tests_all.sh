#!/bin/sh
 $SRCDIR/script/tests/test_ejs.sh $CONFIGURATION
 $SRCDIR/script/tests/test_ldap.sh 
 $SRCDIR/script/tests/test_nbt.sh
 $SRCDIR/script/tests/test_rpc.sh
 $SRCDIR/script/tests/test_net.sh
 $SRCDIR/script/tests/test_session_key.sh
 $SRCDIR/script/tests/test_binding_string.sh
 $SRCDIR/script/tests/test_echo.sh
 $SRCDIR/script/tests/test_posix.sh
 $SRCDIR/script/tests/test_cifs.sh
 $SRCDIR/script/tests/test_local.sh
 $SRCDIR/script/tests/test_pidl.sh
 $SRCDIR/script/tests/test_blackbox.sh $PREFIX/blackbox
 $SRCDIR/script/tests/test_simple.sh
 $SRCDIR/script/tests/test_s3upgrade.sh $PREFIX/upgrade
