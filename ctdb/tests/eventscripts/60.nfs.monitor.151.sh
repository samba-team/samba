#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "mountd down, 1 iteration"

setup_nfs
rpc_services_down "mountd"

ok_null

simple_test
