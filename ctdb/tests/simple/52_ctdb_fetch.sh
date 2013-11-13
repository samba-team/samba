#!/bin/bash

test_info()
{
    cat <<EOF
Run the ctdb_fetch test and sanity check the output.

This doesn't test for performance regressions or similarly anything
useful.  Only vague sanity checking of results is done.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run ctdb_fetch on all nodes with default options.
3. Ensure that the number of +ve and -ive messages are within 1% of
   each other.
4. Ensure that the number of messages per second is greater than 10.

Expected results:

* ctdb_fetch runs without error and prints reasonable results.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

echo "Running ctdb_fetch on all $num_nodes nodes."
try_command_on_node -v -p all $CTDB_TEST_WRAPPER $VALGRIND ctdb_fetch -n $num_nodes

pat='^(Fetch: [[:digit:]]+(\.[[:digit:]]+)? msgs/sec[[:space:]]?|msg_count=[[:digit:]]+ on node [[:digit:]]|Fetching final record|DATA:|Test data|Waiting for cluster[[:space:]]?|.*: Reqid wrap!|Sleeping for [[:digit:]]+ seconds|)+$'
sanity_check_output 1 "$pat" "$out"

# Filter out the performance figures:
out_fetch=$(echo "$out" | egrep '^(Fetch: .*)+$')

# Get the last line of output.
while read line ; do
    prev=$line
done <<<"$out_fetch"

# $prev should look like this:
#    Fetch: 10670.93 msgs/sec
stuff="${prev##*Fetch: }"
mps="${stuff% msgs/sec*}"

if [ ${mps%.*} -ge 10 ] ; then
    echo "OK: $mps msgs/sec >= 10 msgs/sec"
else
    echo "BAD: $mps msgs/sec < 10 msgs/sec"
    exit 1
fi
