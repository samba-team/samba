#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb statistics' works as expected.

This is pretty superficial and could do more validation.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb statistics' on a node, and verify that the output is
   valid.
3. Repeat the command with the '-n all' option and verify that the
   output is valid.

Expected results:

* 'ctdb statistics' shows valid output on all the nodes.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

cluster_is_healthy

pattern='^(CTDB version 1|Gathered statistics for [[:digit:]]+ nodes|[[:space:]]+[[:alpha:]_]+[[:space:]]+[[:digit:]]+|[[:space:]]+(node|client|timeouts)|[[:space:]]+([[:alpha:]_]+_latency|max_reclock_[[:alpha:]]+)[[:space:]]+[[:digit:]-]+\.[[:digit:]]+[[:space:]]sec)$'

try_command_on_node -v 1 "$CTDB statistics"

sanity_check_output 40 "$pattern" "$out"

try_command_on_node -v 1 "$CTDB statistics -n all"

sanity_check_output 40 "$pattern" "$out"
