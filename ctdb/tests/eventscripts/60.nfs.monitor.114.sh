#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "knfsd down, 6 iterations, dump 5 threads, 3 hung"

# knfsd fails and attempts to restart it fail.
setup_nfs
rpc_services_down "nfs"

# Additionally, any hung threads should have stack traces dumped.
CTDB_NFS_DUMP_STUCK_THREADS=5
FAKE_NFSD_THREAD_PIDS="1001 1002 1003"

iterate_test 10 'rpc_set_service_failure_response "nfsd"'
