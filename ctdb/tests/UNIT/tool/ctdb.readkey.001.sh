#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "volatile read"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test_other attach "volatile.tdb"

ok <<EOF
Data: size:0 ptr:[]
EOF
simple_test "volatile.tdb" "key1"
