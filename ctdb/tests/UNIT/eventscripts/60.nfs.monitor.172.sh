#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "nfs down, 10 iterations, not previously healthy"

setup

nfs_iterate_test -i 10 "nfs"
