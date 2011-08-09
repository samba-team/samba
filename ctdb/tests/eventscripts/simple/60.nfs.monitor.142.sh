#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "statd down, 8 iterations, back up after 2"

# statd fails and the first attempt to restart it succeeds.

setup_nfs
rpc_services_down "status"

iterate_test 8 'ok_null' \
    2 'rpc_set_service_failure_response "statd"' \
    3 'rpc_services_up "status"'
