#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all in natgw group, 1 disconnected"

setup_natgw <<EOF
192.168.20.41
192.168.20.42
192.168.20.43
EOF

ctdb_state="\
NODEMAP
0       192.168.20.41   0x1
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
"

#####

required_result 0 <<EOF
1 192.168.20.42
EOF

simple_test master <<EOF
$ctdb_state
EOF

#####

required_result 0 <<EOF
192.168.20.41
192.168.20.42	MASTER
192.168.20.43
EOF

simple_test list <<EOF
$ctdb_state
EOF

#####

required_result 0 <<EOF
pnn:0 192.168.20.41    DISCONNECTED|INACTIVE
pnn:1 192.168.20.42    OK (THIS NODE)
pnn:2 192.168.20.43    OK
EOF

simple_test status <<EOF
$ctdb_state
EOF
