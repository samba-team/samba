#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "rquotad down, 2 iterations"

setup_nfs_ganesha
rpc_services_down "rquotad"

nfs_iterate_test 2 "rquotad"
