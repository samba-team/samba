#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "statd down, 10 iterations"

# statd fails and attempts to restart it fail.

setup_nfs
rpc_services_down "status"

ok_null
simple_test || exit $?

ok<<EOF
Trying to restart statd [rpc.statd]
EOF
simple_test || exit $?

ok_null
simple_test || exit $?

ok<<EOF
ERROR: status failed RPC check:
rpcinfo: RPC: Program not registered
program status version 1 is not available
Trying to restart statd [rpc.statd]
EOF
simple_test || exit $?

ok_null
simple_test || exit $?

required_result 1 <<EOF
ERROR: status failed RPC check:
rpcinfo: RPC: Program not registered
program status version 1 is not available
EOF
simple_test || exit $?
simple_test || exit $?
simple_test || exit $?
simple_test || exit $?

CTDB_NFS_DUMP_STUCK_THREADS=3
FAKE_RPC_THREAD_PIDS=1234

required_result 1 <<EOF
ERROR: status failed RPC check:
rpcinfo: RPC: Program not registered
program status version 1 is not available
Trying to restart statd [rpc.statd]
Stack trace for rpc.statd[1234]:
[<ffffffff87654321>] fake_stack_trace_for_pid_1234/stack+0x0/0xff
EOF
simple_test || exit $?
