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
   all_ips_on_node helper function.

Expected results:

* 'ctdb delip' removes an IP address from the list of public IP
  addresses being served by a node.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

echo "Getting list of public IPs..."
all_ips_on_node -v 0

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
    echo "GOOD: That worked!"
else
    echo "BAD: The remove IP address is still there!"
    testfailures=1
fi
