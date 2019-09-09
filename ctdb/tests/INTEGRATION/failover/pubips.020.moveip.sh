#!/bin/bash

test_info()
{
    cat <<EOF
Verify that  'ctdb moveip' allows movement of public IPs between cluster nodes.

This test does not do any network level checks to make sure IP
addresses are actually on interfaces.  It just consults "ctdb ip".

To work, this test ensures that IPAllocAlgorithm is not set to 0
(Deterministic IPs) and sets NoIPFailback.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

select_test_node_and_ips

sanity_check_ips ()
{
    echo "Sanity checking IPs..."

    local x ipp prev
    prev=""
    while read x ipp ; do
	[ "$ipp" = "-1" ] && break
	if [ -n "$prev" -a "$ipp" != "$prev" ] ; then
	    echo "OK"
	    return 0
	fi
	prev="$ipp"
    done <"$outfile"

    echo "BAD: a node was -1 or IPs are only assigned to one node:"
    cat "$outfile"
    echo "Are you running an old version of CTDB?"
    return 1
}

sanity_check_ips

# Find a target node - it must be willing to host $test_ip
try_command_on_node any "$CTDB listnodes | wc -l"
num_nodes="$out"
to_node=""
for i in $(seq 0 $(($num_nodes - 1)) ) ; do
    [ $i -ne $test_node ] || continue
    all_ips_on_node $i
    while read ip x ; do
	if [ "$ip" = "$test_ip" ] ; then
	    to_node="$i"
	    break 2
	fi
    done <"$outfile"
done

if [ -z "$to_node" ] ; then
    echo "Unable to find target node"
    exit 1
fi

echo "Target node is ${to_node}"

echo "Setting IPAllocAlgorithm=2 to avoid Deterministic IPs..."
try_command_on_node -q all $CTDB setvar IPAllocAlgorithm 2

echo "Turning on NoIPFailback..."
try_command_on_node -q all $CTDB setvar NoIPFailback 1

echo "Attempting to move ${test_ip} from node ${test_node} to node ${to_node}"
try_command_on_node $test_node $CTDB moveip $test_ip $to_node
wait_until_ips_are_on_node '!' $test_node $test_ip
wait_until_ips_are_on_node $to_node $test_ip
