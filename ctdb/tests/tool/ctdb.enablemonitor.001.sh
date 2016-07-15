#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "basic monitor enable"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

ok_null
simple_test_other disablemonitor

ok "DISABLED"
simple_test_other getmonmode

ok_null
simple_test

ok "ENABLED"
simple_test_other getmonmode

# Idempotence

ok_null
simple_test

ok "ENABLED"
simple_test_other getmonmode
