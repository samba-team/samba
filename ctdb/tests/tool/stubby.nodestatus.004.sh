#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "-n all, 3 nodes, 1 disconnected"

# -n all asks each node for the node status and 
#        thus reports THIS NODE for each node

required_result 0 <<EOF
pnn:0 192.168.20.41    OK (THIS NODE)
pnn:2 192.168.20.43    OK (THIS NODE)
EOF

simple_test -n all <<EOF
NODEMAP
0       192.168.20.41   0x0
1       192.168.20.42   0x1
2       192.168.20.43   0x0     CURRENT RECMASTER

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
