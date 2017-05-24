#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "current, 3 nodes, node 0 disabled+stopped, various queries"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x24
1       192.168.20.42   0x0
2       192.168.20.43   0x0     CURRENT RECMASTER

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:
EOF

required_result 36 <<EOF
pnn:0 192.168.20.41    DISABLED|STOPPED|INACTIVE
EOF
simple_test 0

required_result 36 <<EOF
|Node|IP|Disconnected|Banned|Disabled|Unhealthy|Stopped|Inactive|PartiallyOnline|ThisNode|
|0|192.168.20.41|0|0|1|0|1|1|0|N|
EOF
simple_test -X 0

required_result 36 <<EOF
pnn:0 192.168.20.41    DISABLED|STOPPED|INACTIVE
pnn:1 192.168.20.42    OK
EOF
simple_test 0,1

required_result 0 <<EOF
pnn:1 192.168.20.42    OK
pnn:2 192.168.20.43    OK (THIS NODE)
EOF
simple_test 1,2
