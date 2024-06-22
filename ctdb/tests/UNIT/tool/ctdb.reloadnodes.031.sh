#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, 2nd node changes IP address"

setup_nodes <<EOF
192.168.20.41
192.168.20.52
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 <<EOF
Node 1 has changed IP address (was 192.168.20.42, now 192.168.20.52)
ERROR: Nodes will not be reloaded due to previous error
EOF

simple_test
