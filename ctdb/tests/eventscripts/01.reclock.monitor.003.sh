#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "set, exists"

setup

ok_null
simple_test
