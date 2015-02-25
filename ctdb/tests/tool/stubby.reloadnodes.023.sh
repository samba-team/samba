#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, undelete middle"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

ok <<EOF
Node 0 is unchanged
Node 1 is UNDELETED
Node 2 is unchanged
Reloading nodes file on node 0
Reloading nodes file on node 2
ctdb_ctrl_reload_nodes_file: node 0
ctdb_ctrl_reload_nodes_file: node 2
EOF

simple_test <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x11
2       192.168.20.43   0x0

VNNMAP
654321
0
2
EOF
