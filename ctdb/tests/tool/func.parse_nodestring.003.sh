#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all, current disconnected"

required_result 10 <<EOF
${TEST_DATE_STAMP}Unable to get nodemap from local node
EOF

simple_test all true <<EOF
0       192.168.20.41   0x0
1       192.168.20.42   0x0
2       192.168.20.43   0x1     CURRENT RECMASTER
EOF
