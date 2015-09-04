#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, delete middle, add 2 nodes, less debug"

CTDB_DEBUGLEVEL=0

setup_nodes <<EOF
192.168.20.41
#192.168.20.42
192.168.20.43
192.168.20.44
192.168.20.45
EOF

ok_null

simple_test <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x1
2       192.168.20.43   0x0

VNNMAP
654321
0
2
EOF
