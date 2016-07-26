#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "invalid interface"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:0:4:
EOF

required_result 1 <<EOF
Interface eth0 not configured on node 0
EOF
simple_test eth0 down
