#!/bin/bash

# From node 1, disable node 2.  Make sure that according to "ctdb ip"
# the public addresses are taken over and according to "ctdb status"
# the node appears to be disabled.  Don't actually check if the
# address has been correctly taken over.

. ctdb_test_functions.bash

set -e

onnode 0 $TEST_WRAP cluster_is_healthy

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
onnode 0 $TEST_WRAP wait_until_node_has_status 2 disabled

if wait_until_ips_are_on_nodeglob '[!2]' $ips ; then
    echo "All IPs moved."
else
    echo "Some IPs didn't move."
    testfailures=1
fi

echo "Expect a restart here..."

ctdb_test_exit
