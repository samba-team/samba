#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, same ips on all nodes, IPv6, 1 unassigned"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:

PUBLICIPS
10.0.0.31  0
fd00::5357:5f01 2
10.0.0.32  -1
fd00::5357:5f02 1
10.0.0.33  2
fd00::5357:5f03 0
EOF

required_result 0 <<EOF
Public IPs on ALL nodes
10.0.0.31 node[0] active[eth2] available[eth2,eth1] configured[eth2,eth1]
10.0.0.32 node[-1] active[] available[] configured[]
10.0.0.33 node[2] active[eth2] available[eth2,eth1] configured[eth2,eth1]
fd00::5357:5f01 node[2] active[eth2] available[eth2,eth1] configured[eth2,eth1]
fd00::5357:5f02 node[1] active[eth2] available[eth2,eth1] configured[eth2,eth1]
fd00::5357:5f03 node[0] active[eth2] available[eth2,eth1] configured[eth2,eth1]
EOF
simple_test -v all
