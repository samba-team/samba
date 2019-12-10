#!/usr/bin/env bash

# Verify that 'ctdb setvar NoIPTakeover 1' stops IP addresses being taken over

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

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


echo "Turning on NoIPTakeover on all nodes"
try_command_on_node all "$CTDB setvar NoIPTakeover 1"
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
