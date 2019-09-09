#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all services available, not enough nfsd threads"

setup

RPCNFSDCOUNT=8
nfs_setup_fake_threads "nfsd" 1 2 3 4 5

ok "Attempting to correct number of nfsd threads from 5 to 8"

simple_test
