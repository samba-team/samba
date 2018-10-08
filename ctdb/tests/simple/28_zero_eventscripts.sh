#!/bin/bash

test_info()
{
    cat <<EOF
Check that CTDB operated correctly if there are 0 event scripts

This test only does anything with local daemons.  On a real cluster it
has no way of updating configuration.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
	echo "SKIPPING this test - only runs against local daemons"
	exit 0
fi

ctdb_stop_all

echo "Starting CTDB with an empty eventscript directory..."
setup_ctdb --no-event-scripts
ctdb_start_all

wait_until_ready

echo "Good, that seems to work!"

ctdb_stop_all
