#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all, 3 nodes, 1 unhealthy"

required_result 0 <<EOF
Number of nodes:3
pnn:0 192.168.20.41    UNHEALTHY
pnn:1 192.168.20.42    OK (THIS NODE)
pnn:2 192.168.20.43    OK
Generation:654321
Size:3
hash:0 lmaster:0
hash:1 lmaster:1
hash:2 lmaster:2
Recovery mode:NORMAL (0)
Recovery master:1
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
