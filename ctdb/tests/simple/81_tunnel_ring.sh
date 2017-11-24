#!/bin/bash

test_info()
{
    cat <<EOF
Run tunnel_test and sanity check the output.

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

echo "Running tunnel_test on all $num_nodes nodes."
try_command_on_node -v -p all $CTDB_TEST_WRAPPER $VALGRIND \
	tunnel_test -t 30 -n $num_nodes

# Get the last line of output.
while read line ; do
    prev=$line
done <<<"$out"

pat='^(Waiting for cluster|pnn\[[[:digit:]]+\] [[:digit:]]+(\.[[:digit:]]+)? msgs/sec)$'
sanity_check_output 1 "$pat" "$out"

# $prev should look like this:
#    pnn[2] count=85400
stuff="${prev##pnn\[*\] }"
mps="${stuff% msgs/sec}"

if [ ${mps%.*} -ge 10 ] ; then
    echo "OK: $mps msgs/sec >= 10 msgs/sec"
else
    echo "BAD: $mps msgs/sec < 10 msgs/sec"
    exit 1
fi
