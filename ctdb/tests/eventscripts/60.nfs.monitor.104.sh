#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

# Add this extra test to catch a design change where we only ever
# increase the number of threads.  That is, this test would need to be
# consciously removed.
define_test "all services available, check nfsd thread count, too many threads"

setup_nfs

CTDB_MONITOR_NFS_THREAD_COUNT="yes"
RPCNFSDCOUNT=4
FAKE_NFSD_THREAD_PIDS="1 2 3 4 5 6"

ok "Attempting to correct number of nfsd threads from 6 to 4"

simple_test
