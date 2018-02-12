#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 multipath devices configure to check, all up"

setup "mpatha"  "mpathb"  "mpathc"

ok_null

simple_test
