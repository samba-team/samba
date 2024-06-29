#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "nfs down, 1 iteration, not previously healthy"

setup

nfs_iterate_test -i 1 "nfs"
