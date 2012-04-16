#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all interfaces up"

setup_ctdb

ok_null

simple_test
