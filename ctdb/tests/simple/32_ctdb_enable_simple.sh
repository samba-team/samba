#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of 'ctdb enable'.

This is a superficial test of the 'ctdb enable' command.  It trusts
information from CTDB that indicates that the IP failover has happened
correctly.  Another test should check that the failover has actually
happened at the networking level.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Disable one of the nodes using 'ctdb disable -n <node>'.
3. Verify that the status of the node changes to 'disabled'.
4. Verify that the public IP addreses served by the disabled node are
   failed over to other nodes.
5. Enable the disabled node using 'ctdb enable -n '<node>'.
6. Verify that the status changes back to 'OK'.
7. Verify that the public IP addreses served by the disabled node are
   failed back to the node.


Expected results:

* The status of a re-enabled node changes as expected and IP addresses
  fail back as expected.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

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

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

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
onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status 2 disabled

if wait_until_ips_are_on_nodeglob '[!2]' $ips ; then
    echo "All IPs moved."
else
    echo "Some IPs didn't move."
    testfailures=1
fi

echo "Reenabling node 2"
try_command_on_node 1 ctdb enable -n 2

onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status 2 enabled

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

echo "All done!"

ctdb_test_exit
