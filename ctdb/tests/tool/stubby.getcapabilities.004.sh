#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, non-default capabilities"

set -e

input="\
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER CTDB_CAP_LVS
1       192.168.20.42   0x0	-CTDB_CAP_LMASTER
2       192.168.20.43   0x0	-CTDB_CAP_RECMASTER -CTDB_CAP_NATGW

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:

VNNMAP
654321
0
1
2"

required_result 0 <<EOF
RECMASTER: YES
LMASTER: YES
LVS: YES
NATGW: YES
EOF

simple_test -n 0 <<EOF
$input
EOF

required_result 0 <<EOF
RECMASTER: YES
LMASTER: NO
LVS: NO
NATGW: YES
EOF

simple_test -n 1 <<EOF
$input
EOF

required_result 0 <<EOF
RECMASTER: NO
LMASTER: YES
LVS: NO
NATGW: NO
EOF

simple_test -n 2 <<EOF
$input
EOF
