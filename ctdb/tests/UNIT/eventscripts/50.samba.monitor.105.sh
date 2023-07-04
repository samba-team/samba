#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "non-existent share path"

setup

out=$(shares_missing "samba" 2)

required_result 1 "$out"
simple_test
