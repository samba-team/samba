#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all services available"

setup_nfs_ganesha

ok_null

simple_test
