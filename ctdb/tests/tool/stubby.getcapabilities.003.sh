#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, current disconnected"

required_result 10 <<EOF
${TEST_DATE_STAMP}Unable to get nodemap from local node
EOF

simple_test <<EOF
NODEMAP
0       192.168.20.41   0x1     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:

VNNMAP
654321
0
1
2
EOF
