#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "get RPC service fail limits/actions"

setup_nfs

set -e

rm -f "$rpc_fail_limits_file"
CTDB_RC_LOCAL="$CTDB_BASE/rc.local.nfs.monitor.get-limits" \
    "${CTDB_BASE}/events.d/60.nfs" "monitor" >"$rpc_fail_limits_file"

services="knfsd|mountd|rquotad|lockd|statd"

echo "Doing rough check of file format..."

! grep -v -E "^(${services}) " "$rpc_fail_limits_file"
