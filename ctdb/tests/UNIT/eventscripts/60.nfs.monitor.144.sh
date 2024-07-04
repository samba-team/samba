#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "statd down, 7 iterations"

# statd fails and attempts to restart it fail.

setup

nfs_iterate_test 7 "status"
