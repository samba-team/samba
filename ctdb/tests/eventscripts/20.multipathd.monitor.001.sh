#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "No multipath devices configure to check"

setup_multipathd

ok_null

simple_test
