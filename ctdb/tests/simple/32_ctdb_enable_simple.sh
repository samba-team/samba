#!/bin/bash

# From node 1, disable node 2.  Make sure that according to "ctdb ip"
# the public addresses are taken over and according to "ctdb status"
# the node appears to be disabled.  Don't actually check if the
# address has been correctly taken over.

. ctdb_test_functions.bash

# Note that this doesn't work reliably over NFS!
ctdb_trigger_recovered_file="/tmp/ctdb-trigger-recovered"

setup_recovered_trigger ()
{
    onnode -q 0 touch "$ctdb_trigger_recovered_file"
}

recovered_triggered ()
{
    onnode -q 0 '! [ -e "$ctdb_trigger_recovered_file" ]'
}

wait_until_recovered_triggered ()
{
    wait_until 30 recovered_triggered
}

########################################

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

setup_recovered_trigger

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

#echo "Waiting until cluster has recovered..."
#wait_until_recovered_triggered

#echo "Sleeping to avoid potential race..."
#sleep_for 3

echo "Reenabling node 2"
try_command_on_node 1 ctdb enable -n 2

onnode 0 $TEST_WRAP wait_until_node_has_status 2 enabled

# BUG: this is only guaranteed if DeterministicIPs is 1 and
#      NoIPFailback is 0.
if wait_until_ips_are_on_nodeglob '2' $ips ; then
    echo "All IPs moved."
else
    echo "Some IPs didn't move."
    testfailures=1
fi

# Disabling this because for some reason it is completely unreliable.
# Depend even more on the sleep below...
echo "Waiting until cluster has recovered..."
wait_until_recovered_triggered

#echo "Sleeping to avoid potential race..."
#sleep_for 10

echo "All done!"

ctdb_test_exit
