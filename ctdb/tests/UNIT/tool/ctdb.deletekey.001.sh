#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "volatile delete"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test_other attach "volatile.tdb"

ok_null
simple_test "volatile.tdb" "key1"

ok_null
simple_test_other writekey "volatile.tdb" "key1" "value1"

ok <<EOF
Data: size:6 ptr:[value1]
EOF
simple_test_other readkey "volatile.tdb" "key1"

ok_null
simple_test "volatile.tdb" "key1"

ok <<EOF
Data: size:0 ptr:[]
EOF
simple_test_other readkey "volatile.tdb" "key1"
