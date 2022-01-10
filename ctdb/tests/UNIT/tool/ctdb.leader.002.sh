#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "node 2"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT
1       192.168.20.42   0x0
2       192.168.20.43   0x0     RECMASTER 
EOF

ok 2

simple_test
