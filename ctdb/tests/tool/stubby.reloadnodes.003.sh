#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, missing file on 1"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_nodes 1 <<EOF
192.168.20.41
#192.168.20.42
192.168.20.43
EOF

rm "$CTDB_NODES_1"

required_result 255 <<EOF
Failed to read nodes file "${CTDB_NODES_1}"
ERROR: Failed to get nodes file from node 1
EOF

simple_test <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

VNNMAP
654321
0
1
2
EOF
