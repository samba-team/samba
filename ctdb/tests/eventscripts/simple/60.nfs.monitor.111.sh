#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "knfsd down, 1 iteration"

setup_nfs
rpc_services_down "nfs"

ok_null

simple_test
