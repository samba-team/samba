#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of 'ctdb isnotrecmaster'.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb isnotrecmaster' on each node.

3. Verify that only 1 node shows the output 'This node is the
   recmaster' and all the other nodes show the output 'This node is
   not the recmaster'.

Expected results:

* 'ctdb isnotrecmaster' shows the correct output.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

cmd="$CTDB isnotrecmaster || true"
try_command_on_node -v all "$cmd"

num_all_lines=$(wc -l <"$outfile")
num_rm_lines=$(grep -Fc 'this node is the recmaster' "$outfile") || true
num_not_rm_lines=$(grep -Fc 'this node is not the recmaster' "$outfile") || true

if [ $num_rm_lines -eq 1 ] ; then
    echo "OK, there is only 1 recmaster"
else
    die "BAD, there are ${num_rm_lines} nodes claiming to be the recmaster"
fi

if [ $(($num_all_lines - $num_not_rm_lines)) -eq 1 ] ; then
    echo "OK, all the other nodes claim not to be the recmaster"
else
    die "BAD, there are only ${num_not_rm_lines} notrecmaster nodes"
fi
