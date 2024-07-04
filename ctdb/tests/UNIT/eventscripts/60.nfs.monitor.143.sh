#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "statd down, 2 iterations, stuck process"

# statd fails and the first attempt to restart it succeeds.

setup

nfs_setup_fake_threads "rpc.status" 1001

nfs_iterate_test 2 "status"
