#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "statd down, 6 iterations"

# statd fails and attempts to restart it fail.

setup_nfs
rpc_services_down "status"

iterate_test 6 'ok_null' \
    2 'rpc_set_service_failure_response "statd"' \
    4 'rpc_set_service_failure_response "statd"' \
    6 'rpc_set_service_failure_response "statd"'
