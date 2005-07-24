$SRCDIR/script/tests/test_ejs.sh localhost $USERNAME $PASSWORD || failed=`expr $failed + $?`
$SRCDIR/script/tests/test_ldap.sh localhost $USERNAME $PASSWORD || failed=`expr $failed + $?`
$SRCDIR/script/tests/test_nbt.sh localhost || failed=`expr $failed + $?`
$SRCDIR/script/tests/test_quick.sh //localhost/cifs $USERNAME $PASSWORD "" || failed=`expr $failed + $?`

