#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, no IPs"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 0 <<EOF
No nodes available to host public IPs yet
EOF
test_takeover_helper

required_result 0 <<EOF
Public IPs on ALL nodes
EOF
test_ctdb_ip_all
