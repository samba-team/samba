#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "knfsd down, 10 iterations, dump 5 threads, 3 hung"

# knfsd fails and attempts to restart it fail.
setup_nfs
rpc_services_down "nfs"

# Additionally, any hung threads should have stack traces dumped.
CTDB_NFS_DUMP_STUCK_THREADS=5
nfs_setup_fake_threads "nfsd" 1001 1002 1003

nfs_iterate_test 10 "nfs"
