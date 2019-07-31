#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set to default lock file, directory is created"

setup

dir=$(dirname "$CTDB_RECOVERY_LOCK")

# Ensure directory doesn't exist before
required_result 1 ""
unit_test test -d "$dir"

ok_null
simple_test

# Ensure directory exists after
ok_null
unit_test test -d "$dir"
