#!/bin/bash

. ctdb_test_functions.bash

set -e

echo "Restartng ctdb on all nodes..."
restart_ctdb
