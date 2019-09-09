#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "current, 3 nodes, node 0 unhealthy"

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

required_result 0 <<EOF
pnn:2 192.168.20.43    OK (THIS NODE)
EOF
simple_test

required_result 0 <<EOF
|Node|IP|Disconnected|Banned|Disabled|Unhealthy|Stopped|Inactive|PartiallyOnline|ThisNode|
|2|192.168.20.43|0|0|0|0|0|0|0|Y|
EOF
simple_test -X
