#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of 'ctdb disable'.

This is a superficial test of the 'ctdb disable' command.  It trusts
information from CTDB that indicates that the IP failover has happened
correctly.  Another test should check that the failover has actually
happened at the networking level.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Disable one of the nodes using 'ctdb disable -n <node>'.
3. Verify that the status of the node changes to 'disabled'.
4. Verify that the IP addreses served by the disabled node are failed
   over to other nodes.

Expected results:

* The status of the disabled node changes as expected and IP addresses
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

echo "Disabling node 2"

try_command_on_node 1 ctdb disable -n 2

# Avoid a potential race condition...
onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status 2 disabled

if wait_until_ips_are_on_nodeglob '[!2]' $ips ; then
    echo "All IPs moved."
else
    echo "Some IPs didn't move."
    testfailures=1
fi

echo "Expect a restart..."

ctdb_test_exit
