#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Just a recovery"

setup_ctdbd <<EOF
NODEMAP
0	192.168.20.41	0x0	CURRENT
1	192.168.20.42	0x0	RECMASTER
2	192.168.20.43	0x0

VNNMAP
654321
0
1
2
EOF

ok_null

simple_test
