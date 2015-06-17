#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "lockd down, 15 iterations"

# This simulates an ongoing failure in the eventscript's automated
# attempts to restart the service.  That is, the eventscript is unable
# to restart the service.

setup_nfs
rpc_services_down "nlockmgr"

iterate_test 15 "ok_null" \
    10 "rpc_set_service_failure_response 'nlockmgr'" \
    15 "rpc_set_service_failure_response 'nlockmgr'"
