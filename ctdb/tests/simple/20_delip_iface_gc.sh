#!/bin/bash

test_info()
{
    cat <<EOF
Verify that an interface is deleted when all IPs on it are deleted.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

select_test_node_and_ips

# Find interfaces on test node
try_command_on_node $test_node "$CTDB ifaces -X"
ifaces=$(awk -F'|' 'NR > 1 { print $2 }' "$outfile")
echo "Node ${test_node} has interfaces: ${ifaces}"

# Delete all IPs on each interface...  deleting IPs from one interface
# can cause other interfaces to disappear, so we need to be careful...
for i in $ifaces ; do
    try_command_on_node $test_node "$CTDB ifaces -X"
    info=$(awk -F'|' -v iface="$i" '$2 == iface { print $0 }' "$outfile")

    if [ -z "$info" ] ; then
	echo "Interface ${i} missing... assuming already deleted!"
	continue
    fi

    echo "Deleting IPs on interface ${i}, with this information:"
    echo " $info"

    try_command_on_node $test_node "$CTDB ip -v -X | tail -n +2"
    awk -F'|' -v i="$i" \
	'$6 == i { print $2 }' "$outfile" |
    while read ip ; do
	echo "  $ip"
	try_command_on_node $test_node "$CTDB delip $ip"
    done
    try_command_on_node $test_node "$CTDB ipreallocate"

    try_command_on_node $test_node "$CTDB ifaces -X"
    info=$(awk -F'|' -v iface="$i" '$2 == iface { print $0 }' "$outfile")

    if [ -z "$info" ] ; then
	echo "GOOD: Interface ${i} has been garbage collected"
    else
	echo "BAD: Interface ${i} still exists"
	echo "$out"
	exit 1
    fi
done
