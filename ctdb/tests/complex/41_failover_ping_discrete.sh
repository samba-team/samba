#!/bin/bash

test_info()
{
    cat <<EOF
Verify that it is possible to ping a public address after disabling a node.

We ping a public IP, disable the node hosting it and then ping the
public IP again.

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.

* Test must not be run from a cluster node.

Steps:

1. Verify that the cluster is healthy.
2. Select a public address and its corresponding node.
3. Send a single ping request packet to the selected public address.
4. Disable the selected node.
5. Send another single ping request packet to the selected public address.

Expected results:

* When a node is disabled the public address fails over and the
  address is still pingable.
EOF
}

. ctdb_test_functions.bash

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

echo "Getting list of public IPs..."
try_command_on_node 0 "$CTDB ip -n all | sed -e '1d'"

# When selecting test_node we just want a node that has public IPs.
# This will work and is economically semi-randomly.  :-)
read x test_node <<<"$out"

ips=""
while read ip pnn ; do
    if [ "$pnn" = "$test_node" ] ; then
	ips="${ips}${ips:+ }${ip}"
    fi
done <<<"$out" # bashism to avoid problem setting variable in pipeline.

echo "Selected node ${test_node} with IPs: $ips"

test_ip="${ips%% *}"

echo "Removing ${test_ip} from the local ARP table..."
arp -d $test_ip >/dev/null 2>&1 || true

echo "Pinging ${test_ip}..."
ping -q -n -c 1 $test_ip

filter="arp net ${test_ip}"
tcpdump_start "$filter"

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node disabled

tcpdump_wait 2

echo "GOOD: this should be the gratuitous ARP and the reply:"
tcpdump_show

echo "Removing ${test_ip} from the local ARP table again..."
arp -d $test_ip >/dev/null 2>&1 || true

echo "Pinging ${test_ip} again..."
ping -q -n -c 1 $test_ip
