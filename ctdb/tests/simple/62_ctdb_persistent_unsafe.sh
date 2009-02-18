#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the ctdb_persistent test succeeds for unsafe persistent writes.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run two copies of ctdb_persistent on each node with a 30 second
   timeout and with the --unsafe-writes option.
3. Ensure that all ctdb_persistent processes complete successfully.

Expected results:

* ctdb_persistent tests unsafe persistent writes without error.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

t="$CTDB_TEST_WRAPPER $VALGRIND ctdb_persistent --unsafe-writes --timelimit=30"

echo "Running ctdb_persistent --unsafe-writes on all $num_nodes nodes."
try_command_on_node -v -pq all "$t & $t"

ctdb_test_exit
