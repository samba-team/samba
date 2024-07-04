#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "portmapper down, 2 iterations"

setup

nfs_iterate_test 2 "portmapper"
