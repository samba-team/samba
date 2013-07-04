#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "rquotad down"

setup_nfs_ganesha
rpc_services_down "rquotad"

ok<<EOF
ERROR: rquotad failed RPC check:
rpcinfo: RPC: Program not registered
program rquotad version 1 is not available
Trying to restart rquotad [rpc.rquotad]
EOF

simple_test
