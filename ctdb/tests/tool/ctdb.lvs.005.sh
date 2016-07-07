#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all LVS, all unhealthy"

setup_lvs <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x2	CURRENT RECMASTER
1       192.168.20.42   0x2
2       192.168.20.43   0x2
EOF

#####

required_result 0 <<EOF
0
EOF

simple_test master

#####

required_result 0 <<EOF
0 192.168.20.41
1 192.168.20.42
2 192.168.20.43
EOF

simple_test list

#####

required_result 0 <<EOF
pnn:0 192.168.20.41    UNHEALTHY (THIS NODE)
pnn:1 192.168.20.42    UNHEALTHY
pnn:2 192.168.20.43    UNHEALTHY
EOF

simple_test status
