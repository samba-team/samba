#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all healthy, IPs very unbalanced, force rebalance all"

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
10.0.0.34  2
10.0.0.35  2
10.0.0.36  2
EOF

ok <<EOF
Forcing rebalancing of IPs to node 1
Forcing rebalancing of IPs to node 0
Forcing rebalancing of IPs to node 2
EOF
test_takeover_helper 1,0,2

required_result 0 <<EOF
Public IPs on ALL nodes
10.0.0.31 0
10.0.0.32 1
10.0.0.33 2
10.0.0.34 2
10.0.0.35 0
10.0.0.36 1
EOF
test_ctdb_ip_all
