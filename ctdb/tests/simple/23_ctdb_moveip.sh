#!/bin/bash

test_info()
{
    cat <<EOF
Verify that  'ctdb moveip' allows movement of public IPs between cluster nodes.

To work, this test unsets DeterministicIPs and sets NoIPFailback.

This test does not do any network level checks that the IP address is
no longer reachable but simply trusts 'ctdb ip' that the address has
been deleted.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Use 'ctdb ip' on one of the nodes to list the IP addresses being
   served.
3. Use 'ctdb moveip' to move an address from one node to another.
4. Verify that the IP is no longer being hosted by the first node and is now being hosted by the second node.

Expected results:

* 'ctdb moveip' allows an IP address to be moved between cluster nodes.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

# Restart when done since things are likely to be broken.
ctdb_test_exit_hook="restart_ctdb"

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"
echo "There are $num_nodes nodes..."

if [ $num_nodes -lt 2 ] ; then
    echo "Less than 2 nodes!"
    exit 1
fi

echo "Getting list of public IPs..."
try_command_on_node -v 0 "$CTDB ip -n all | sed -e '1d'"

sanity_check_ips "$out"

# Select an IP/node to move.
num_ips=$(echo "$out" | wc -l)
num_to_move=$(($RANDOM % $num_ips))

# Find the details in the list.
i=0
while [ $i -le $num_to_move ] ; do
    read ip_to_move test_node
    i=$(($i + 1))
done <<<"$out"

# Can only move address to a node that is willing to host $ip_to_move.
# This inefficient but shouldn't take long or get stuck.
to_node=$test_node
while [ $test_node -eq $to_node ] ; do
    n=$(($RANDOM % $num_ips))
    i=0
    while [ $i -le $n ] ; do
	read x to_node
	i=$(($i + 1))
    done <<<"$out"
done

echo "Turning off DeterministicIPs..."
try_command_on_node 0 $CTDB setvar DeterministicIPs 0 -n all

echo "Turning on NoIPFailback..."
try_command_on_node 0 $CTDB setvar NoIPFailback 1 -n all

echo "Attempting to move ${ip_to_move} from node ${test_node} to node ${to_node}."
try_command_on_node $test_node $CTDB moveip $ip_to_move $to_node

if wait_until_ips_are_on_nodeglob "[!${test_node}]" $ip_to_move ; then
    echo "IP moved from ${test_node}."
else
    echo "BAD: IP didn't move from ${test_node}."
    exit 1
fi

if wait_until_ips_are_on_nodeglob "$to_node" $ip_to_move ; then
    echo "IP moved to ${to_node}."
else
    echo "BAD: IP didn't move to ${to_node}."
    exit 1
fi

echo "OK, that worked... expect a restart..."

ctdb_test_exit
