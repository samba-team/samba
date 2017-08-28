#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "persistent delete"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test_other attach "persistent.tdb" persistent

ok_null
simple_test_other pstore "persistent.tdb" "key1" "value1"

ok_null
simple_test "persistent.tdb" "key1"

ok_null
simple_test_other pfetch "persistent.tdb" "key1"

ok "0x2"
simple_test_other getdbseqnum "persistent.tdb"
