#!/usr/bin/env bash

# Check that CTDB operates correctly if there are 0 event scripts


. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init -n

ctdb_nodes_start_custom --no-event-scripts

echo "Good, that seems to work!"
