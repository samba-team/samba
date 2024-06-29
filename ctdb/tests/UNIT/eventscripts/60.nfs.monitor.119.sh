#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "NFS RPC service timeout, silent stats error, 10 iterations"

# It would be nice to have a non-silent stats error... but that's a
# bit hard for the current test code to handle.  :-(

setup

cat >"${CTDB_BASE}/nfs-checks.d/20.nfs.check" <<EOF
# nfs
version="3"
restart_every=10
unhealthy_after=2
service_stop_cmd="\$CTDB_NFS_CALLOUT stop nfs"
service_start_cmd="\$CTDB_NFS_CALLOUT start nfs"
service_debug_cmd="program_stack_traces nfsd 5"
service_stats_cmd="false"
EOF

nfs_iterate_test 10 "nfs:TIMEOUT"
