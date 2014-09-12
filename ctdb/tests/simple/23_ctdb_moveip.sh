#!/bin/bash

test_info()
{
    cat <<EOF
Verify that  'ctdb moveip' allows movement of public IPs between cluster nodes.

This test does not do any network level checks to make sure IP
addresses are actually on interfaces.  It just consults "ctdb ip".

To work, this test unsets DeterministicIPs and sets NoIPFailback.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

sanity_check_ips "$out"

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
    done <<<"$out"
done

if [ -z "$to_node" ] ; then
    echo "Unable to find target node"
    exit 1
fi

echo "Target node is ${to_node}"

echo "Turning off DeterministicIPs..."
try_command_on_node 0 $CTDB setvar DeterministicIPs 0 -n all

echo "Turning on NoIPFailback..."
try_command_on_node 0 $CTDB setvar NoIPFailback 1 -n all

echo "Attempting to move ${test_ip} from node ${test_node} to node ${to_node}"
try_command_on_node $test_node $CTDB moveip $test_ip $to_node
wait_until_ips_are_on_node '!' $test_node $test_ip
wait_until_ips_are_on_node $to_node $test_ip
