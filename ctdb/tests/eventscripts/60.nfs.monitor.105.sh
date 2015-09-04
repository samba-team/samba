#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all services available, 10 iterations with ok_null"

setup_nfs

ok_null
nfs_iterate_test 10
