#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "not managed, check no-op"

setup_nfs "down"

ok_null

simple_test
