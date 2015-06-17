#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "rquotad down, 5 iterations, back up after 1"

# rquotad fails once but then comes back of its own accord after 1
# failure.

setup_nfs
rpc_services_down "rquotad"

nfs_iterate_test 5 "rquotad" \
    2 'rpc_services_up "rquotad"'
