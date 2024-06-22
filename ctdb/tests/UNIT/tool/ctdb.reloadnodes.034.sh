#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, list reversed nodes change IP address"

setup_nodes <<EOF
192.168.20.43
192.168.20.42
192.168.20.41
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 <<EOF
Node 0 has changed IP address (was 192.168.20.41, now 192.168.20.43)
Node 2 has changed IP address (was 192.168.20.43, now 192.168.20.41)
ERROR: Nodes will not be reloaded due to previous error
EOF

simple_test
