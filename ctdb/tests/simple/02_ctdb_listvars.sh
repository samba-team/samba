#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb listvars' shows a list of all tunable variables.

This test simply checks that at least 5 sane looking lines are
printed.  It does not check that the list is complete or that the
values are sane.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb listvars' and verify that it shows a list of tunable
   variables and their current values.

Expected results:

* 'ctdb listvars' works as expected.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

try_command_on_node -v 0 "$CTDB listvars"

sanity_check_output \
    5 \
    '^[[:alpha:]]+[[:space:]]*=[[:space:]]*[[:digit:]]+$' \
    "$out"

ctdb_test_exit
