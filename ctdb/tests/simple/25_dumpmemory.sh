#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb dumpmemory' shows expected output.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb dumpmemory' and verify that it shows expected output
3. Verify that the command takes the '-n all' option and that it
   causes output for all nodes to be displayed.

Expected results:

* 'ctdb dumpmemory' sows valid output.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node -v 0 "$CTDB dumpmemory"

pat='^([[:space:]].+[[:space:]]+contains[[:space:]]+[[:digit:]]+ bytes in[[:space:]]+[[:digit:]]+ blocks \(ref [[:digit:]]+\)[[:space:]]+0x[[:xdigit:]]+|[[:space:]]+reference to: .+|full talloc report on .+ \(total[[:space:]]+[[:digit:]]+ bytes in [[:digit:]]+ blocks\))$'

sanity_check_output 10 "$pat" "$out"

echo "Checking output using '-n all'..."

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

try_command_on_node 0 "$CTDB dumpmemory" -n all
sanity_check_output 10 "$pat" "$out"

if [ $(fgrep -c 'full talloc report on' <<<"$out") -eq  $num_nodes ] ; then
    echo "OK: there looks to be output for all $num_nodes nodes"
else
    echo "BAD: there not look to be output for all $num_nodes nodes"
    exit 1
fi    
