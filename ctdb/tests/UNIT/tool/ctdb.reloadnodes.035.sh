#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, comment at beginning, deleted node, nodes move"

setup_nodes <<EOF
# Adding a comment!
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 <<EOF
Node 0 is DELETED
ERROR: Node 0 is still connected
Node 1 has changed IP address (was 192.168.20.42, now 192.168.20.41)
Node 2 has changed IP address (was 192.168.20.43, now 192.168.20.42)
ERROR: Nodes will not be reloaded due to previous error
EOF

simple_test
