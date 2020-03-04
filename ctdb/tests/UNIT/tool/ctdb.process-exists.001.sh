#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "ctdbd process on node 0"

ctdb_test_check_supported_OS "Linux"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

dummy_client -s $ctdbd_socket &
pid=$!

wait_until 10 $CTDB process-exists "$pid"

ok "PID $pid exists"
simple_test "$pid"

kill -9 $pid

pid=$(ctdbd_getpid)
required_result 1 "PID $pid does not exist"
simple_test "$pid"
