#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "lockd down, 7 iterations, back up after 2"

# This simulates a success the eventscript's automated attempts to
# restart the service.

setup

rpc_services_down "nlockmgr"

# Iteration 2 should try to restart rpc.lockd.  However, our test
# stub rpc.lockd does nothing, so we have to explicitly flag it as up.

nfs_iterate_test 7 "nlockmgr" \
    3 "rpc_services_up nlockmgr"
