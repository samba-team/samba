#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, GET_NODEMAP timeout"

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
10.0.0.31  1
10.0.0.32  1
10.0.0.33  1

CONTROLFAILS
91	0	TIMEOUT	CTDB_CONTROL_GET_NODEMAP fake timeout
EOF

required_error ETIMEDOUT <<EOF
control GET_NODEMAP failed to node 0, ret=$(errcode ETIMEDOUT)
takeover run failed, ret=$(errcode ETIMEDOUT)
EOF
test_takeover_helper
