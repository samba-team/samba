#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "rquotad down"

setup_nfs_ganesha
rpc_services_down "rquotad"

rpc_set_service_failure_response "rquotad"
simple_test
