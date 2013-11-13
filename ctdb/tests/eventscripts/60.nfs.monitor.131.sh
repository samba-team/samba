#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "rquotad down, 5 iterations"

setup_nfs
rpc_services_down "rquotad"

iterate_test 5 'rpc_set_service_failure_response "rquotad"'
