#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set to use helper, check no-op"

setup "!/bin/false"

ok_null
simple_test
