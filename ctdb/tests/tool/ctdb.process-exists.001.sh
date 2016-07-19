#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "ctdbd process on node 0"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

pid=$(ctdbd_getpid)

ok "PID $pid exists"
simple_test "$pid"

# Use a PID that is probably impossible.  It must fit into 32 bits but
# should be larger than most settings for pid_max.
required_result 1 "PID 99999999 does not exist"
simple_test "99999999"
