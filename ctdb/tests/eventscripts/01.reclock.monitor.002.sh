#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set to helper, check no-op"

CTDB_RECOVERY_LOCK="!/some/recover/lock/helper foo"

ok_null
simple_test
