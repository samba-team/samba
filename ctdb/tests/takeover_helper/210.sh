#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all ok, no IPs, IPREALLOCATED timeout"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

CONTROLFAILS
137	1	TIMEOUT	CTDB_CONTROL_IPREALLOCATED fake timeout

EOF

required_error ETIMEDOUT <<EOF
No nodes available to host public IPs yet
IPREALLOCATED failed on node 1, ret=$(errcode ETIMEDOUT)
Assigning banning credits to node 1
takeover run failed, ret=$(errcode ETIMEDOUT)
EOF
test_takeover_helper

required_result 0 <<EOF
Public IPs on ALL nodes
EOF
test_ctdb_ip_all
