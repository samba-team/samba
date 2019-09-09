#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, same ips on all nodes"

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
10.0.0.32  1
10.0.0.33  2
EOF

required_result 0 <<EOF
Public IP[10.0.0.32] info on node 0
IP:10.0.0.32
CurrentNode:1
NumInterfaces:2
Interface[1]: Name:eth2 Link:up References:2 (active)
Interface[2]: Name:eth1 Link:up References:4
EOF
simple_test 10.0.0.32
