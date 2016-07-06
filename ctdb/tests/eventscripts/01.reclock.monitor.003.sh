#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set, exists"

setup_reclock

ok_null
simple_test
