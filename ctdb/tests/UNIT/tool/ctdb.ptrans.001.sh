#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "persistent transactions"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test_other attach "persistent.tdb" persistent

ok_null
simple_test_other pstore "persistent.tdb" "key0" "value0"

ok_null
simple_test "persistent.tdb" <<EOF
"key1" "value1"
"key2" "value2"
"key1" ""
"key2" "value3"
EOF

ok "value0"
simple_test_other pfetch "persistent.tdb" "key0"

ok_null
simple_test_other pfetch "persistent.tdb" "key1"

ok "value3"
simple_test_other pfetch "persistent.tdb" "key2"

ok "0x2"
simple_test_other getdbseqnum "persistent.tdb"

ok_null
simple_test "persistent.tdb" <<EOF
"key0" "value0"
EOF

ok "value0"
simple_test_other pfetch "persistent.tdb" "key0"

ok "0x2"
simple_test_other getdbseqnum "persistent.tdb"
