#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, undelete middle"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x11
2       192.168.20.43   0x0
EOF

ok <<EOF
Node 1 is UNDELETED
EOF

simple_test
