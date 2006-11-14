#!/bin/sh
 $SRCDIR/script/tests/test_net.sh $SERVER $USERNAME $PASSWORD $DOMAIN || failed=`expr $failed + $?`
