#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "knfsd down, 10 iterations, no hung threads"

# knfsd fails and attempts to restart it fail.
setup

rpc_services_down "nfs"

nfs_setup_fake_threads "nfsd"

nfs_iterate_test 10 "nfs"
