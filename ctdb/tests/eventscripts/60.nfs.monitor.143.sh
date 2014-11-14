#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "statd down, 2 iterations, stuck process"

# statd fails and the first attempt to restart it succeeds.

setup_nfs
rpc_services_down "status"
CTDB_NFS_DUMP_STUCK_THREADS=2
FAKE_RPC_THREAD_PIDS="1001"

iterate_test 2 'ok_null' \
    2 'rpc_set_service_failure_response "statd"'
