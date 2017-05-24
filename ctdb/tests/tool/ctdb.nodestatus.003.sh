#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all, 3 nodes, 1 unhealthy"

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
Number of nodes:3
pnn:0 192.168.20.41    UNHEALTHY
pnn:1 192.168.20.42    OK
pnn:2 192.168.20.43    OK (THIS NODE)
EOF
simple_test all

required_result 2 <<EOF
|Node|IP|Disconnected|Banned|Disabled|Unhealthy|Stopped|Inactive|PartiallyOnline|ThisNode|
|0|192.168.20.41|0|0|0|1|0|0|0|N|
|1|192.168.20.42|0|0|0|0|0|0|0|N|
|2|192.168.20.43|0|0|0|0|0|0|0|Y|
EOF
simple_test -X all
