#!/bin/bash

. ctdb_test_functions.bash

set -e

onnode 0 $TEST_WRAP cluster_is_healthy

try_command_on_node 0 "ctdb listnodes"

num_nodes=$(echo "$out" | wc -l)

echo "Output for \"ctdb listnodes\" on node 0 (${num_nodes} nodes listed):"
echo "$out"

# Each line should look like an IP address.
sanity_check_output \
    2 \
    '^[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+$' \
    "$out"

out_0="$out"

echo "Checking other nodes..."

n=1
while [ $n -lt $num_nodes ] ; do
    echo -n "Node ${n}: "
    try_command_on_node $n "ctdb listnodes"
    if [ "$out_0" = "$out" ] ; then
	echo "OK"
    else
	echo "DIFFERs from node 0:"
	echo "$out"
	testfailures=1
    fi
    n=$(($n + 1))
done

ctdb_test_exit
