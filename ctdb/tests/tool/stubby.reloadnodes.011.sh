#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, add a node"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
192.168.20.44
EOF

required_result 0 <<EOF
Node 0 is unchanged
Node 1 is unchanged
Node 2 is unchanged
Node 3 is NEW
Reloading nodes file on node 0
Reloading nodes file on node 1
Reloading nodes file on node 2
ctdb_ctrl_reload_nodes_file: node 0
ctdb_ctrl_reload_nodes_file: node 1
ctdb_ctrl_reload_nodes_file: node 2
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
