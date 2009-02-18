#!/bin/bash

test_info()
{
    cat <<EOF
Verify that an IP address can be added to a node using 'ctdb addip'.

This test goes to some trouble to figure out which IP address to add
but assumes a 24-bit subnet mask.  It does not handle IPv6.  It does
not do any network level checks that the new IP address is reachable
but simply trusts 'ctdb ip' that the address has been added.  There is
also an extra prerequisite that the node being added to already has
public addresses - this is difficult to avoid if the extra address is
to be sensibly chosen.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Use 'ctdb ip' on one of the nodes to list the IP addresses being
   served.
3. Add an additional public address to be served by the node, using
   'ctdb addip'.
4. Verify that this IP address has been added to the list of IP
   addresses being served by the node, using the 'ctdb ip' command.

Expected results:

* 'ctdb ip' adds an IP address to the list of public IP addresses
  being served by a node.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

echo "Getting list of public IPs..."
try_command_on_node 0 "$CTDB ip -n all | sed -e '1d'"

# When selecting test_node we just want a node that has public IPs.
# This will work and is economically semi-randomly.  :-)
read x test_node <<<"$out"

test_node_ips=""
all_ips=""
while read ip pnn ; do
    all_ips="${all_ips}${all_ips:+ }${ip}"
    [ "$pnn" = "$test_node" ] && \
	test_node_ips="${test_node_ips}${test_node_ips:+ }${ip}"
done <<<"$out"

echo "Selected node ${test_node} with IPs: $test_node_ips"

# Try to find a free IP adddress.  This is inefficient but should
# succeed quickly.
try_command_on_node $test_node "ip addr show"
all_test_node_ips=$(echo "$out" | sed -rn -e 's@^[[:space:]]+inet[[:space:]]+([[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+/[[:digit:]]+).*[[:space:]]([^[:space:]]+)+$@\1:\2@p')

add_ip=""

# Use an IP already on one of the nodes, remove the last octet and
# loop through the possible IP addreses.
for i in $test_node_ips ; do
    prefix="${i%.*}"
    for j in $(seq 1 254) ; do
	try="${prefix}.${j}"
	# Try to make sure it isn't used anywhere!

	# First, make sure it isn't an existing public address on the
	# cluster.
	for k in $all_ips ; do
	    [ "$try" = "$k" ] && continue 2
	done

	# Also make sure it isn't some other address in use on the
	# node.
	for k in $all_test_node_ips ; do
	    [ "$try" = "${k%/*}" ] && continue 2
	done

	# Get the interface details for $i, which our address is a
	# close relative of.  This should never fail but it can't hurt
	# to be careful...
	for k in $all_test_node_ips ; do
	    if [ "$i" = "${k%/*}" ] ; then
			# Found one!
		add_ip="${try}/${k#*/}"
		break 3
	    fi
	done
    done
done

if [ -n "$add_ip" ] ; then
    echo "Adding IP: ${add_ip/:/ on interface }"
    try_command_on_node $test_node $CTDB addip ${add_ip/:/ }

    echo "Waiting for IP to be added..."
    wait_until 60 ips_are_on_nodeglob $test_node $test_node_ips ${add_ip%/*}

    echo "That worked!"
else
    echo "BAD: Unable to find IP address to add."
    testfailures=1
fi

echo "Restarting cluster to restore configuration..."
restart_ctdb

ctdb_test_exit
