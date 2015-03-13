#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Single node reload"

required_result 0 <<EOF
Fake reload public IPs on node 0
Fake takeover run on recovery master 1
EOF

simple_test <<EOF
NODEMAP
0	192.168.20.41	0x0	CURRENT
1	192.168.20.42	0x0	RECMASTER
2	192.168.20.43	0x0
EOF
