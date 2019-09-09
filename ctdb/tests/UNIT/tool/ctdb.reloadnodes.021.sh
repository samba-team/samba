#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, 1 disconnected, add a node"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
192.168.20.44
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x1
2       192.168.20.43   0x0
EOF

required_result 0 <<EOF
WARNING: Node 1 is disconnected. You MUST fix this node manually!
Node 3 is NEW
EOF

simple_test
