#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all services available, check nfsd thread count, count matches"

setup_nfs

CTDB_MONITOR_NFS_THREAD_COUNT="yes"
RPCNFSDCOUNT=8
FAKE_NFSD_THREAD_PIDS="1 2 3 4 5 6 7 8"

ok_null

simple_test
