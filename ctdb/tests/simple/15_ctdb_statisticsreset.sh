#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb statisticsreset' works as expected.

This is pretty superficial.  It just checks that a few particular
items reduce.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb statisticsreset' on all nodes and verify that it executes
   successfully.

Expected results:

* 'ctdb statisticsreset' executes successfully.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

get_stat ()
{
    local label="$1"
    local out="$2"

    echo "$out" | sed -rn -e "s@^[[:space:]]+${label}[[:space:]]+([[:digit:]])@\1@p" | head -1
}

check_reduced ()
{
    local label="$1"
    local before="$2"
    local after="$3"

    if [ $after -lt $before ] ; then
	echo "GOOD: ${label} reduced from ${before} to ${after}"
    else
	echo "BAD: ${label} did not reduce from ${before} to ${after}"
	testfailures=1
    fi
}

n=0
while [ $n -lt $num_nodes ] ; do
    echo "Getting initial statistics for node ${n}..."
    
    try_command_on_node -v $n $CTDB statistics

    before_req_control=$(get_stat "req_control" "$out")
    before_reply_control=$(get_stat "reply_control" "$out")
    before_node_packets_recv=$(get_stat "node_packets_recv" "$out")

    try_command_on_node $n $CTDB statisticsreset

    try_command_on_node -v $n $CTDB statistics

    after_req_control=$(get_stat "req_control" "$out")
    after_reply_control=$(get_stat "reply_control" "$out")
    after_node_packets_recv=$(get_stat "node_packets_recv" "$out")

    check_reduced "req_control" "$before_req_control" "$after_req_control"
    check_reduced "reply_control" "$before_reply_control" "$after_reply_control"
    check_reduced "node_packets_recv" "$before_node_packets_recv" "$after_node_packets_recv"

    n=$(($n + 1))
done
