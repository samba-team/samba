#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, no ips"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 <<EOF
Control GET_PUBLIC_IP_INFO failed, ret=-1
Node 0 does not know about IP 10.0.0.31
EOF
simple_test 10.0.0.31
