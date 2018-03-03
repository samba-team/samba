#!/bin/bash

test_info()
{
    cat <<EOF
Restart the ctdbd daemons of a CTDB cluster.

No error if ctdbd is not already running on the cluster.

Prerequisites:

* Nodes must be accessible via 'onnode'.

Steps:

1. Restart the ctdb daemons on all nodes using a method according to
   the test environment and platform.

Expected results:

* The cluster is healthy within a reasonable timeframe.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

ctdb_stop_all >/dev/null 2>&1 || true

setup_ctdb

ctdb_start_all
