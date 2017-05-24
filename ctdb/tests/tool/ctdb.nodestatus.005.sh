#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "current, 3 nodes, node 0 unhealthy, query node 0"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x2
1       192.168.20.42   0x0
2       192.168.20.43   0x0     CURRENT RECMASTER

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:
EOF

required_result 2 <<EOF
pnn:0 192.168.20.41    UNHEALTHY
EOF
simple_test 0

required_result 2 <<EOF
|Node|IP|Disconnected|Banned|Disabled|Unhealthy|Stopped|Inactive|PartiallyOnline|ThisNode|
|0|192.168.20.41|0|0|0|1|0|0|0|N|
EOF
simple_test -X 0
