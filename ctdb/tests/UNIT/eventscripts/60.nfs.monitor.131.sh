#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "rquotad down, 7 iterations"

setup

rpc_services_down "rquotad"

nfs_iterate_test 7 "rquotad"
