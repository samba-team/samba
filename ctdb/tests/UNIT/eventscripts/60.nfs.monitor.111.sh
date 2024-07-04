#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "knfsd down, 1 iteration"

setup

nfs_iterate_test 1 "nfs"
