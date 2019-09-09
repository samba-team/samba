#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, delete last, add 2 nodes"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
#192.168.20.43
192.168.20.44
192.168.20.45
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x1
EOF

required_result 0 <<EOF
Node 2 is DELETED
Node 3 is NEW
Node 4 is NEW
EOF

simple_test
