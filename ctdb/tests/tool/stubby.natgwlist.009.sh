#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all in natgw group, 1 actual time-out"

setup_natgw <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

required_result 255 <<EOF
${TEST_DATE_STAMP}__LOCATION__ control timed out. reqid:1234567890 opcode:80 dstnode:0
${TEST_DATE_STAMP}__LOCATION__ ctdb_control_recv failed
${TEST_DATE_STAMP}__LOCATION__ ctdb_ctrl_getcapabilities_recv failed
${TEST_DATE_STAMP}Unable to get capabilities from node 0
EOF

simple_test <<EOF
NODEMAP
0       192.168.20.41   0x0     TIMEOUT
1       192.168.20.42   0x0     CURRENT RECMASTER
2       192.168.20.43   0x0

VNNMAP
654321
0
1
2

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:
EOF
