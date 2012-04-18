#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "lockd down, 15 iterations, back up after 10"

# This simulates a success the eventscript's automated attempts to
# restart the service.

setup_nfs
rpc_services_down "nlockmgr"

# Iteration 10 should try to restart rpc.lockd.  However, our test
# stub rpc.lockd does nothing, so we have to explicitly flag it as up.

iterate_test 15 "ok_null" \
    10 "rpc_set_service_failure_response 'lockd'" \
    11 "rpc_services_up nlockmgr"

