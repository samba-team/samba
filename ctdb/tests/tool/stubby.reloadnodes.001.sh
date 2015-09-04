#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, no change"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

ok <<EOF
Node 0 is unchanged
Node 1 is unchanged
Node 2 is unchanged
No change in nodes file, skipping unnecessary reload
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
