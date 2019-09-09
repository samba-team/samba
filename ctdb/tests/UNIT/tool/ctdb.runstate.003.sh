#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "check non-RUNNING states"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

for i in "INIT" "SETUP" "FIRST_RECOVERY" "STARTUP" "SHUTDOWN" ; do
	required_result 1 "CTDB not in required run state (got RUNNING)"
	simple_test "$i"
done
