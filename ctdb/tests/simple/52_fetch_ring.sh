#!/bin/bash

test_info()
{
    cat <<EOF
Run the fetch_ring test and sanity check the output.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

echo "Running fetch_ring on all $num_nodes nodes."
try_command_on_node -v -p all $CTDB_TEST_WRAPPER $VALGRIND fetch_ring -n $num_nodes

pat='^(Waiting for cluster|Fetch\[[[:digit:]]+\]: [[:digit:]]+(\.[[:digit:]]+)? msgs/sec)$'
sanity_check_output 1 "$pat" "$out"

# Get the last line of output.
while read line ; do
    prev=$line
done <<<"$out"

# $prev should look like this:
#    Fetch[1]: 10670.93 msgs/sec
stuff="${prev##*Fetch\[*\]: }"
mps="${stuff% msgs/sec*}"

if [ ${mps%.*} -ge 10 ] ; then
    echo "OK: $mps msgs/sec >= 10 msgs/sec"
else
    echo "BAD: $mps msgs/sec < 10 msgs/sec"
    exit 1
fi
