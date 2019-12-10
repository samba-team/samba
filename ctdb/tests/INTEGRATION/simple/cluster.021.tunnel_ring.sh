#!/usr/bin/env bash

# Run tunnel_test and sanity check the output

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

echo "Running tunnel_test on all $num_nodes nodes."
try_command_on_node -v -p all $CTDB_TEST_WRAPPER $VALGRIND \
	tunnel_test -t 30 -n $num_nodes

# Get the last line of output.
last=$(tail -n 1 "$outfile")

pat='^(Waiting for cluster|pnn\[[[:digit:]]+\] [[:digit:]]+(\.[[:digit:]]+)? msgs/sec)$'
sanity_check_output 1 "$pat"

# $last should look like this:
#    pnn[2] count=85400
stuff="${last##pnn\[*\] }"
mps="${stuff% msgs/sec}"

if [ ${mps%.*} -ge 10 ] ; then
    echo "OK: $mps msgs/sec >= 10 msgs/sec"
else
    echo "BAD: $mps msgs/sec < 10 msgs/sec"
    exit 1
fi
