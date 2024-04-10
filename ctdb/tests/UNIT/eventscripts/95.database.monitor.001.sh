#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "No backup directory set, does nothing"

setup

ok_null
simple_test
