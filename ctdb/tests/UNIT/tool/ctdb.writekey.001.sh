#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "volatile write"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test_other attach "volatile.tdb"

ok_null
simple_test "volatile.tdb" "key1" "value1"

ok <<EOF
Data: size:6 ptr:[value1]
EOF
simple_test_other readkey "volatile.tdb" "key1"

ok_null
simple_test "volatile.tdb" "key1" "a new value"

ok <<EOF
Data: size:11 ptr:[a new value]
EOF
simple_test_other readkey "volatile.tdb" "key1"
