#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "basic interface listing test"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:
EOF

ok <<EOF
Interfaces on node 0
name:eth2 link:up references:2
name:eth1 link:up references:4
EOF
simple_test
