#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "statd down, 6 iterations"

# statd fails and attempts to restart it fail.

setup_nfs_ganesha
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
