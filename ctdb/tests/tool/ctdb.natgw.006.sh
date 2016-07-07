#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, node 0 is slave-only, all stopped"

setup_natgw <<EOF
192.168.20.41	slave-only
192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x20
1       192.168.20.42   0x20    CURRENT RECMASTER
2       192.168.20.43   0x20
EOF

#####

required_result 0 <<EOF
1 192.168.20.42
EOF

simple_test master

#####

required_result 0 <<EOF
192.168.20.41	slave-only
192.168.20.42	MASTER
192.168.20.43
EOF

simple_test list

#####

required_result 0 <<EOF
pnn:0 192.168.20.41    STOPPED|INACTIVE
pnn:1 192.168.20.42    STOPPED|INACTIVE (THIS NODE)
pnn:2 192.168.20.43    STOPPED|INACTIVE
EOF

simple_test status
