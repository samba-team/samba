if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_net.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

DC_SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3

failed=0

net_tool="$BINDIR/net"

# Load test functions
. `dirname $0`/subunit.sh

testit "leave" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit "join+server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD -S$DC_SERVER || failed=`expr $failed + 1`

testit "leave+server" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD -S$DC_SERVER || failed=`expr $failed + 1`

testit_expect_failure "join+invalid_server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD -SINVALID && failed=`expr $failed + 1`

testit "join+server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit_expect_failure "leave+invalid_server" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD -SINVALID && failed=`expr $failed + 1`

testit "testjoin" $VALGRIND $net_tool ads testjoin -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit "testjoin_machine_account" $VALGRIND $net_tool ads testjoin -kP || failed=`expr $failed + 1`

exit $failed
