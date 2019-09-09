#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "simple getpid"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

pid=$(ctdbd_getpid)
ok "$pid"

simple_test
