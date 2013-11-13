#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "mountd down, 10 iterations, back up after 5"

setup_nfs
rpc_services_down "mountd"

# Iteration 5 should try to restart rpc.mountd.  However, our test
# stub rpc.mountd does nothing, so we have to explicitly flag it as
# up.
iterate_test 10 "ok_null" \
    5 "rpc_set_service_failure_response 'mountd'" \
    6 "rpc_services_up mountd"
