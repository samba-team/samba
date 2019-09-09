#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "mountd down, 7 iterations, back up after 2"

setup

rpc_services_down "mountd"

# Iteration 2 should try to restart rpc.mountd.  However, our test
# stub rpc.mountd does nothing, so we have to explicitly flag it as
# up.
nfs_iterate_test 7 "mountd" \
    3 "rpc_services_up mountd"
