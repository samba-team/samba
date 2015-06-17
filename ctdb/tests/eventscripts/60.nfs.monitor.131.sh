#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "rquotad down, 5 iterations"

setup_nfs
rpc_services_down "rquotad"

nfs_iterate_test 5 "rquotad"
