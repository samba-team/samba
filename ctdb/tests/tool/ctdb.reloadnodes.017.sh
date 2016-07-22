#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, delete connected middle node"

setup_nodes <<EOF
192.168.20.41
#192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 <<EOF
Node 1 is DELETED
ERROR: Node 1 is still connected
ERROR: Nodes will not be reloaded due to previous error
EOF

simple_test
