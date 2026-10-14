#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

# Takes several minutes under valgrind, so do fewer iterations
if [ -n "$VALGRIND" ]; then
	max=100
else
	max=1000
fi

ok_null

unit_test protocol_types_test 1 "$max"
