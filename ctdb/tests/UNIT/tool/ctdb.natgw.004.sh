#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all unhealthy, all but 1 stopped"

setup_natgw <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x22
1       192.168.20.42   0x22     CURRENT RECMASTER
2       192.168.20.43   0x2
EOF

#####

required_result 0 <<EOF
2 192.168.20.43
EOF

simple_test master

#####

required_result 0 <<EOF
192.168.20.41
192.168.20.42
192.168.20.43	MASTER
EOF

simple_test list

#####

required_result 0 <<EOF
pnn:0 192.168.20.41    UNHEALTHY|STOPPED|INACTIVE
pnn:1 192.168.20.42    UNHEALTHY|STOPPED|INACTIVE (THIS NODE)
pnn:2 192.168.20.43    UNHEALTHY
EOF

simple_test status
