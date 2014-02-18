#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all LVS, all ok"

required_result 0 <<EOF
0:192.168.20.41
1:192.168.20.42
2:192.168.20.43
EOF

simple_test <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER CTDB_CAP_LVS
1       192.168.20.42   0x0	CTDB_CAP_LVS
2       192.168.20.43   0x0	CTDB_CAP_LVS

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
