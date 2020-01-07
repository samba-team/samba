#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, GET_PID control times out"

setup_lvs <<EOF
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

CONTROLFAILS
30 0 TIMEOUT  # Make "ctdb getpid" time out
EOF

#####

required_result 1 <<EOF
Maximum runtime exceeded - exiting
EOF
simple_test -T 3
