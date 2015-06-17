#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "knfsd down, 10 iterations"

# knfsd fails and attempts to restart it fail.

setup_nfs
rpc_services_down "nfs"

iterate_test 10 'rpc_set_service_failure_response "nfs"'
