#!/bin/bash

test_info()
{
    cat <<EOF
Run the ctdb_bench test and sanity check the output.

This doesn't test for performance regressions or similarly anything
useful.  Only vague sanity checking of results is done.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run ctdb_bench on all nodes with default options.
3. Ensure that the number of +ve and -ive messages are within 1% of
   each other.
4. Ensure that the number of messages per second is greater than 10.

Expected results:

* ctdb_bench runs without error and prints reasonable results.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

echo "Running ctdb_bench on all $num_nodes nodes."
try_command_on_node -v -p all $CTDB_TEST_WRAPPER $VALGRIND ctdb_bench -n $num_nodes

# Get the last line of output.
while read line ; do
    prev=$line
done <<<"$out"

pat='^(Ring: [[:digit:]]+(\.[[:digit:]]+)? msgs/sec \(\+ve=[[:digit:]]+ -ve=[[:digit:]]+\)[[:space:]]?|Waiting for cluster[[:space:]]?)+$'
sanity_check_output 1 "$pat" "$out"

# $prev should look like this:
#    Ring: 10670.93 msgs/sec (+ve=53391 -ve=53373)
stuff="${prev##*Ring: }"
mps="${stuff% msgs/sec*}"

if [ ${mps%.*} -ge 10 ] ; then
    echo "OK: $mps msgs/sec >= 10 msgs/sec"
else
    echo "BAD: $mps msgs/sec < 10 msgs/sec"
    exit 1
fi

stuff="${stuff#*msgs/sec (+ve=}"
positive="${stuff%% *}"

if [ $positive -gt 0 ] ; then
    echo "OK: +ive ($positive) > 0"
else
    echo "BAD: +ive ($positive) = 0"
    exit 1
fi

stuff="${stuff#*-ve=}"
negative="${stuff%)}"

if [ $negative -gt 0 ] ; then
    echo "OK: -ive ($negative) > 0"
else
    echo "BAD: -ive ($negative) = 0"
    exit 1
fi

perc_diff=$(( ($positive - $negative) * 100 / $positive ))
perc_diff=${perc_diff#-}

check_percent=5
if [ $perc_diff -le $check_percent ] ; then
    echo "OK: percentage difference between +ive and -ive ($perc_diff%) <= $check_percent%"
else
    echo "BAD: percentage difference between +ive and -ive ($perc_diff%) > $check_percent%"
    exit 1
fi
