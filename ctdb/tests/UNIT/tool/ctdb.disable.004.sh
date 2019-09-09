#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "invalid node"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 "Node 4 does not exist"
simple_test -n 4
