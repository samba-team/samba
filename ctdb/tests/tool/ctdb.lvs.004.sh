#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all LVS, node 0 unhealthy"

setup_lvs <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x2	CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

#####

required_result 0 <<EOF
1
EOF

simple_test master

#####

required_result 0 <<EOF
1 192.168.20.42
2 192.168.20.43
EOF

simple_test list

#####

required_result 0 <<EOF
pnn:0 192.168.20.41    UNHEALTHY (THIS NODE)
pnn:1 192.168.20.42    OK
pnn:2 192.168.20.43    OK
EOF

simple_test status
