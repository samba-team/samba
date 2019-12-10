#!/usr/bin/env bash

# Run the fetch_ring test and sanity check the output

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

echo "Running fetch_ring on all $num_nodes nodes."
testprog_onnode -v -p all \
		fetch_ring -n "$num_nodes" -D "fetch_ring.tdb" -k "testkey"

pat='^(Waiting for cluster|Fetch\[[[:digit:]]+\]: [[:digit:]]+(\.[[:digit:]]+)? msgs/sec)$'
sanity_check_output 1 "$pat"

# Get the last line of output.
last=$(tail -n 1 "$outfile")

# $last should look like this:
#    Fetch[1]: 10670.93 msgs/sec
stuff="${last##*Fetch\[*\]: }"
mps="${stuff% msgs/sec*}"

if [ ${mps%.*} -ge 10 ] ; then
    echo "OK: $mps msgs/sec >= 10 msgs/sec"
else
    echo "BAD: $mps msgs/sec < 10 msgs/sec"
    exit 1
fi
