#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "portmapper down, 2 iterations"

setup

rpc_services_down "portmapper"

nfs_iterate_test 2 "portmapper"
