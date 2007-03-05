#!/bin/sh
 $SRCDIR/script/tests/test_ejs.sh $DOMAIN $USERNAME $PASSWORD $CONFIGURATION
 $SRCDIR/script/tests/test_ldap.sh $SERVER $USERNAME $PASSWORD
 $SRCDIR/script/tests/test_nbt.sh $SERVER
 $SRCDIR/script/tests/test_rpc.sh $SERVER $USERNAME $PASSWORD $DOMAIN
 $SRCDIR/script/tests/test_net.sh $SERVER $USERNAME $PASSWORD $DOMAIN
 $SRCDIR/script/tests/test_session_key.sh $SERVER $USERNAME $PASSWORD $DOMAIN $NETBIOSNAME
 $SRCDIR/script/tests/test_binding_string.sh $SERVER $USERNAME $PASSWORD $DOMAIN
 $SRCDIR/script/tests/test_echo.sh $SERVER $USERNAME $PASSWORD $DOMAIN
 $SRCDIR/script/tests/test_posix.sh //$SERVER/tmp $USERNAME $PASSWORD ""
 $SRCDIR/script/tests/test_local.sh
 $SRCDIR/script/tests/test_pidl.sh
 $SRCDIR/script/tests/test_blackbox.sh $SERVER $USERNAME $PASSWORD $DOMAIN $PREFIX
 $SRCDIR/script/tests/test_simple.sh //$SERVER/simple $USERNAME $PASSWORD ""
 $SRCDIR/script/tests/test_s3upgrade.sh $PREFIX/upgrade
