#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Single node reload, more debug"

CTDB_DEBUGLEVEL=4

required_result 0 <<EOF
Disable takeover runs reply received from node 0
Disable takeover runs reply received from node 1
Disable takeover runs reply received from node 2
Fake reload public IPs on node 0
Enable takeover runs reply received from node 0
Enable takeover runs reply received from node 1
Enable takeover runs reply received from node 2
Fake takeover run on recovery master 1
EOF

simple_test <<EOF
NODEMAP
0	192.168.20.41	0x0	CURRENT
1	192.168.20.42	0x0	RECMASTER
2	192.168.20.43	0x0
EOF
