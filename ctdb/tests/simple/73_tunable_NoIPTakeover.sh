#!/bin/bash

test_info()
{
    cat <<EOF
Verify that  'ctdb setvar NoIPTakeover 1' stops ip addresses from being failed 
over onto the node.

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

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"
echo "There are $num_nodes nodes..."

if [ $num_nodes -lt 2 ] ; then
    echo "Less than 2 nodes!"
    exit 1
fi


echo "Wait until the ips are reallocated"
sleep_for 30
try_command_on_node 0 "$CTDB ipreallocate"

num=`try_command_on_node -v 1 "$CTDB ip" | grep -v Public | egrep " 1$" | wc -l`
echo "Number of addresses on node 1 : $num"


echo "Turning on NoIPTakeover on node 1"
try_command_on_node 1 "$CTDB setvar NoIPTakeover 1"
try_command_on_node 1 "$CTDB ipreallocate"

echo Disable node 1
try_command_on_node 1 "$CTDB disable"
try_command_on_node 1 "$CTDB ipreallocate"
num=`try_command_on_node -v 1 "$CTDB ip" | grep -v Public | egrep " 1$" | wc -l`
echo "Number of addresses on node 1 : $num"
[ "$num" != "0" ] && {
    echo "BAD: node 1 still hosts ip addresses"
    exit 1
}


echo "Enable node 1 again"
try_command_on_node 1 "$CTDB enable"
sleep_for 30
try_command_on_node 1 "$CTDB ipreallocate"
try_command_on_node 1 "$CTDB ipreallocate"
num=`try_command_on_node -v 1 "$CTDB ip" | grep -v Public | egrep " 1$" | wc -l`
echo "Number of addresses on node 1 : $num"
[ "$num" != "0" ] && {
    echo "BAD: node took over ip addresses"
    exit 1
}


echo "OK. ip addresses were not taken over"
exit 0
