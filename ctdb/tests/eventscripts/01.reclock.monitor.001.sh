#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "unset, check no-op"

CTDB_RECOVERY_LOCK=""

ok_null
simple_test
