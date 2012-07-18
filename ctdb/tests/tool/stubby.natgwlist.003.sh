#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, 2 in natgw group, 1 unhealthy"

setup_natgw <<EOF
192.168.20.41
192.168.20.43
EOF

required_result 0 <<EOF
2 192.168.20.43
Number of nodes:2
pnn:0 192.168.20.41    UNHEALTHY
pnn:2 192.168.20.43    OK
EOF

simple_test <<EOF
NODEMAP
0       192.168.20.41   0x2
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
