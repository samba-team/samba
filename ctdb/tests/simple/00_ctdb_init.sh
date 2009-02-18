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

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

echo "Restarting ctdb on all nodes..."
setup_ctdb
restart_ctdb
