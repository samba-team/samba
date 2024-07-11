#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, comment added at end, new deleted node"

setup_nodes <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
# Adding a comment!
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok <<EOF
Node 3 is NEW
EOF
simple_test

ok <<EOF
Number of nodes:4 (including 1 deleted nodes)
pnn:0 192.168.20.41    OK (THIS NODE)
pnn:1 192.168.20.42    OK
pnn:2 192.168.20.43    OK
EOF
simple_test_other nodestatus all
