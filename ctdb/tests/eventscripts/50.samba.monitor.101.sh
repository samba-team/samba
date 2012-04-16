#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all OK"

setup_samba

ok_null

simple_test
