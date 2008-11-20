#!/bin/bash

. ctdb_test_functions.bash

set -e

onnode 0 $TEST_WRAP cluster_is_healthy

try_command_on_node 0 "ctdb listvars"

echo "Output from \"ctdb listvars\" on node 0:"
echo "$out"

sanity_check_output \
    5 \
    '^[[:alpha:]]+[[:space:]]*=[[:space:]]*[[:digit:]]+$' \
    "$out"

ctdb_test_exit
