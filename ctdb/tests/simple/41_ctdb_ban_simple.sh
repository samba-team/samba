#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of the 'ctdb ban' command.

This is a superficial test of the 'ctdb ban' command.  It trusts
information from CTDB that indicates that the IP failover has
happened correctly.  Another test should check that the failover
has actually happened at the networking level.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Ban one of the nodes using the 'ctdb ban <timeout>' command.
3. Before the ban timeout expires, verify that the status of the
   node changes to 'banned'.
4. Verify that the public IP addresses that were being served by
   the node are failed over to one of the other nodes.
5. When the ban expires ensure that the status of the node changes
   back to 'OK' and that the public IP addresses move back to the
   node.

Expected results:

* The status of the banned nodes changes as expected and IP addresses
  failover as expected.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

try_command_on_node 1 ctdb ip -n all

ips=""
while read ip pnn ; do
    if [ "$pnn" = "2" ] ; then
	ips="${ips}${ips:+ }${ip}"
    fi
done <<<"$out" # bashism to avoid problem setting variable in pipeline.

echo "Node 2 has IPs: $ips"

ban_time=15

echo "Banning node 2 for $ban_time seconds"
try_command_on_node 1 ctdb ban $ban_time -n 2

# Avoid a potential race condition...
onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status 2 banned

if wait_until_ips_are_on_nodeglob '[!2]' $ips ; then
    echo "All IPs moved."
else
    echo "Some IPs didn't move."
    testfailures=1
fi

echo "Sleeping until ban expires..."
sleep_for $ban_time

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status 2 unbanned

# BUG: this is only guaranteed if DeterministicIPs is 1 and
#      NoIPFailback is 0.
if wait_until_ips_are_on_nodeglob '2' $ips ; then
    echo "All IPs moved."
else
    echo "Some IPs didn't move."
    testfailures=1
fi

echo "Sleeping to avoid potential race..."
sleep_for 3

ctdb_test_exit
