#!/bin/bash

test_info()
{
    cat <<EOF
Restart the ctdbd daemons of a CTDB cluster.

Ensure that event script reequired for cluster tests are enabled.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

ctdb_test_check_real_cluster

ctdb_stop_all >/dev/null 2>&1 || true

ctdb_enable_cluster_test_event_scripts

ctdb_start_all
