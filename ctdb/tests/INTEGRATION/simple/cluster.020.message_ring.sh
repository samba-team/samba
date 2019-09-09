#!/bin/bash

test_info()
{
    cat <<EOF
Run the message_ring test and sanity check the output.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

echo "Running message_ring on all $num_nodes nodes."
try_command_on_node -v -p all $CTDB_TEST_WRAPPER $VALGRIND message_ring -n $num_nodes

# Get the last line of output.
last=$(tail -n 1 "$outfile")

pat='^(Waiting for cluster|Ring\[[[:digit:]]+\]: [[:digit:]]+(\.[[:digit:]]+)? msgs/sec \(\+ve=[[:digit:]]+ -ve=[[:digit:]]+\))$'
sanity_check_output 1 "$pat"

# $last should look like this:
#    Ring[1]: 10670.93 msgs/sec (+ve=53391 -ve=53373)
stuff="${last##Ring\[*\]: }"
mps="${stuff% msgs/sec*}"

if [ ${mps%.*} -ge 10 ] ; then
    echo "OK: $mps msgs/sec >= 10 msgs/sec"
else
    echo "BAD: $mps msgs/sec < 10 msgs/sec"
    exit 1
fi

stuff="${stuff#*msgs/sec (+ve=}"
positive="${stuff%% *}"

if [ $positive -ge 10 ] ; then
    echo "OK: +ive ($positive) >= 10"
else
    echo "BAD: +ive ($positive) < 10"
    exit 1
fi

stuff="${stuff#*-ve=}"
negative="${stuff%)}"

if [ $negative -ge 10 ] ; then
    echo "OK: -ive ($negative) >= 10"
else
    echo "BAD: -ive ($negative) < 10"
    exit 1
fi
