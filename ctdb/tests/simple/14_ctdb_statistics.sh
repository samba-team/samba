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

pattern='^(CTDB version 1|Current time of statistics[[:space:]]*:.*|Statistics collected since[[:space:]]*:.*|Gathered statistics for [[:digit:]]+ nodes|[[:space:]]+[[:alpha:]_]+[[:space:]]+[[:digit:]]+|[[:space:]]+(node|client|timeouts)|[[:space:]]+([[:alpha:]_]+_latency|max_reclock_[[:alpha:]]+)[[:space:]]+[[:digit:]-]+\.[[:digit:]]+[[:space:]]sec|[[:space:]]*(reclock_ctdbd|reclock_recd|call_latency|lockwait_latency|childwrite_latency)[[:space:]]+MIN/AVG/MAX[[:space:]]+[-.[:digit:]]+/[-.[:digit:]]+/[-.[:digit:]]+ sec out of [[:digit:]]+|[[:space:]]+hop_count_buckets:[[:space:][:digit:]]+)$'

try_command_on_node -v 1 "$CTDB statistics"

sanity_check_output 40 "$pattern" "$out"

try_command_on_node -v 1 "$CTDB statistics -n all"

sanity_check_output 40 "$pattern" "$out"
