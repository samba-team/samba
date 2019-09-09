#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all services available, check nfsd thread count, count matches"

setup

RPCNFSDCOUNT=8
nfs_setup_fake_threads "nfsd" 1 2 3 4 5 6 7 8

ok_null

simple_test
