#!/usr/bin/env bash

# Check that CTDB operates correctly if there are 0 event scripts


. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init --no-event-scripts

cluster_is_healthy

echo "Good, that seems to work!"
