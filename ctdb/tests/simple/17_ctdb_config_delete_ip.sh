#!/bin/bash

test_info()
{
    cat <<EOF
Verify that a node's public IP address can be deleted using 'ctdb deleteip'.

This test does not do any network level checks that the IP address is
no longer reachable but simply trusts 'ctdb ip' that the address has
been deleted.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Use 'ctdb ip' on one of the nodes to list the IP addresses being
   served.
3. Delete one public IP address being be served by the node, using
   'ctdb delip'.
4. Verify that the delete IP address is no longer listed using the
   'ctdb ip' command.

Expected results:

* 'ctdb delip' removes an IP address from the list of public IP
  addresses being served by a node.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

echo "Getting list of public IPs..."
try_command_on_node -v 0 "$CTDB ip -n all | sed -e '1d'"

# Select an IP/node to remove.
num_ips=$(echo "$out" | wc -l)
num_to_remove=$(($RANDOM % $num_ips))

# Find the details in the list.
i=0
while [ $i -le $num_to_remove ] ; do
    read ip_to_remove test_node
    i=$(($i + 1))
done <<<"$out"

echo "Attempting to remove ${ip_to_remove} from node ${test_node}."
try_command_on_node $test_node $CTDB delip $ip_to_remove

echo "Sleeping..."
sleep_for 1

test_node_ips=""
while read ip pnn ; do
    [ "$pnn" = "$test_node" ] && \
	test_node_ips="${test_node_ips}${test_node_ips:+ }${ip}"
done <<<"$out" # bashism to avoid problem setting variable in pipeline.

if [ "${test_node_ips/${ip_to_remove}}" = "$test_node_ips" ] ; then
    echo "That worked!  Restarting cluster to restore configuration..."
    restart_ctdb
else
    echo "BAD: The remove IP address is still there!"
    testfailures=1
fi

ctdb_test_exit
