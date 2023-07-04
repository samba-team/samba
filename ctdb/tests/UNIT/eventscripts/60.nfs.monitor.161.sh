#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "2nd share missing"

setup

out=$(shares_missing "nfs" 2)

required_result 1 "$out"
simple_test
