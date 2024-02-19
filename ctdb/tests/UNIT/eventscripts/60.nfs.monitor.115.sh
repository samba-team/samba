#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "NFS RPC service down, stats change, 10 iterations"

setup

cat >"${CTDB_BASE}/nfs-checks.d/20.nfs.check" <<EOF
# nfs
version="3"
restart_every=10
unhealthy_after=2
service_stop_cmd="\$CTDB_NFS_CALLOUT stop nfs"
service_start_cmd="\$CTDB_NFS_CALLOUT start nfs"
service_debug_cmd="program_stack_traces nfsd 5"
# Dummy pipeline confirms that pipelines work in this context
service_stats_cmd="date --rfc-3339=ns | grep ."
EOF

# Test flag to indicate that stats are expected to change
nfs_stats_set_changed "nfs" "status"

rpc_services_down "nfs"

nfs_iterate_test 10 "nfs"
