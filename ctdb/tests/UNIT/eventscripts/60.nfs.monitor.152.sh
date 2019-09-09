#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "mountd down, 7 iterations"

# This simulates an ongoing failure in the eventscript's automated
# attempts to restart the service.  That is, the eventscript is unable
# to restart the service.

setup

rpc_services_down "mountd"

nfs_iterate_test 7 "mountd"
