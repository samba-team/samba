#!/bin/bash

test_info()
{
    cat <<EOF
Check that CTDB operates correctly if the recovery lock is configured
as a command.

This test only does anything with local daemons.  On a real cluster it
has no way of updating configuration.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

echo "Starting CTDB with recovery lock command configured..."
ctdb_test_init -R

cluster_is_healthy

echo "Good, that seems to work!"
