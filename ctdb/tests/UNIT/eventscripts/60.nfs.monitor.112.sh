#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "knfsd down, 10 iterations"

# knfsd fails and attempts to restart it fail.

setup

nfs_iterate_test 10 "nfs"
