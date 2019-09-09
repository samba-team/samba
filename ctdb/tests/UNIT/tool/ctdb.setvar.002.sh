#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "invalid variable"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

required_result 1 <<EOF
No such tunable TheQuickBrownFoxJumpsOverTheLazyDog
EOF
simple_test "TheQuickBrownFoxJumpsOverTheLazyDog" 42
