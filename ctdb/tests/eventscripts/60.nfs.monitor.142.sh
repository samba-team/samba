#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "statd down, 7 iterations, back up after 2"

# statd fails and the first attempt to restart it succeeds.

setup

rpc_services_down "status"

nfs_iterate_test 7 "status" \
    3 'rpc_services_up "status"'
