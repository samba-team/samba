#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "rquotad down, 7 iterations, back up after 2"

# rquotad fails once but then comes back after restart after 2nd
# failure.

setup

rpc_services_down "rquotad"

nfs_iterate_test 7 "rquotad" \
    3 'rpc_services_up "rquotad"'
