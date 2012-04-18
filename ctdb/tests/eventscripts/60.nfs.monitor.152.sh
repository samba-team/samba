#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "mountd down, 10 iterations"

# This simulates an ongoing failure in the eventscript's automated
# attempts to restart the service.  That is, the eventscript is unable
# to restart the service.

setup_nfs
rpc_services_down "mountd"

iterate_test 10 "ok_null" \
    5 "rpc_set_service_failure_response 'mountd'" \
    10 "rpc_set_service_failure_response 'mountd'"

#export FAKE_NETSTAT_TCP_ESTABLISHED="10.0.0.1:2049|10.254.254.1:12301 10.0.0.1:2049|10.254.254.1:12302 10.0.0.1:2049|10.254.254.1:12303 10.0.0.1:2049|10.254.254.2:12304 10.0.0.1:2049|10.254.254.2:12305"
