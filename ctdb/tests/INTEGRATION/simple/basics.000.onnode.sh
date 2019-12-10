#!/usr/bin/env bash

# Use 'onnode' to confirm connectivity between all cluster nodes

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

echo "Checking connectivity between nodes..."
onnode all onnode -p all hostname
