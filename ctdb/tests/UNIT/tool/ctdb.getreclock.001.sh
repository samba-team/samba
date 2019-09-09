#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "No reclock set"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null

simple_test
