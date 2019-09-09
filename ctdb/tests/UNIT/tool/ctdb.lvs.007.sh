#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all LVS, all nodes disabled"

setup_lvs <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x4	CURRENT RECMASTER
1       192.168.20.42   0x4
2       192.168.20.43   0x4
EOF

#####

required_result 255 <<EOF
EOF

simple_test master

#####

required_result 0 <<EOF
EOF

simple_test list

#####

required_result 0 <<EOF
pnn:0 192.168.20.41    DISABLED (THIS NODE)
pnn:1 192.168.20.42    DISABLED
pnn:2 192.168.20.43    DISABLED
EOF

simple_test status
