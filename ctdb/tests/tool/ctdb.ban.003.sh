#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "already banned"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x8
2       192.168.20.43   0x0
EOF

ok "Node 1 is already banned"
simple_test 60 -n 1

required_result 8 <<EOF
Number of nodes:3
pnn:0 192.168.20.41    OK (THIS NODE)
pnn:1 192.168.20.42    BANNED|INACTIVE
pnn:2 192.168.20.43    OK
EOF
simple_test_other nodestatus all
