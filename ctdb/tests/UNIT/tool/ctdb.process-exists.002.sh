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

srvid="0xaebbccdd12345678"

dummy_client -d INFO -s "$ctdbd_socket" -S "$srvid" &
pid=$!

wait_until 10 $CTDB process-exists "$pid"

srvid2="0x1234567812345678"
required_result 1 "PID $pid with SRVID $srvid2 does not exist"
simple_test "$pid" "$srvid2"

ok "PID $pid with SRVID $srvid exists"
simple_test "$pid" "$srvid"

kill -9 $pid
