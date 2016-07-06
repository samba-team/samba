#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set, doesn't exist, 4 times"

setup_reclock
rm -f "$CTDB_RECOVERY_LOCK"

ok_null
for i in $(seq 1 3) ; do
	simple_test
done

for i in $(seq 4 199) ; do
	required_result 1 <<EOF
ERROR: ${i} consecutive failures checking reclock
EOF
	simple_test
done

required_result 1 <<EOF
Reclock file "${CTDB_RECOVERY_LOCK}" can not be accessed. Shutting down.
Filesystem             1024-blocks      Used Available Capacity Mounted on
/dev/sda1                               1000000     100000     900000         10% /
CTDB says BYE!
EOF
simple_test
