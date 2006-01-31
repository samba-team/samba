 $SRCDIR/script/tests/test_smbclient.sh $SERVER $USERNAME $PASSWORD $DOMAIN $PREFIX || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_cifsdd.sh $SERVER $USERNAME $PASSWORD $DOMAIN || failed=`expr $failed + $?`
