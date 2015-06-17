#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "statd down, 10 iterations"

# statd fails and attempts to restart it fail.

setup_nfs_ganesha
rpc_services_down "status"

nfs_iterate_test 10 "status"
