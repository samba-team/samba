#!/bin/bash

test_info()
{
    cat <<EOF
Verify that an interface is deleted when all IPs on it are deleted.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

echo "Getting public IPs information..."
try_command_on_node -v any "$CTDB ip -v -n all -X | tail -n +2"
ip_info="$out"

# Select the first node and find out its interfaces
test_node=$(awk -F'|' 'NR == 1 { print $3}' <<<"$ip_info")
ifaces=$(awk -F'|' -v tn=$test_node '$3 == tn { print $6 }' <<<"$ip_info" | sed 's@, @ @g' | xargs -n 1 | sort -u)
echo "Selected test node ${test_node} with interfaces: ${ifaces}"

# Delete all IPs on each interface...  deleting IPs from one interface
# can cause other interfaces to disappear, so we need to be careful...
for i in $ifaces ; do
    try_command_on_node $test_node "$CTDB ifaces -X"
    info=$(awk -F'|' -v iface="$i" '$2 == iface { print $0 }' <<<"$out")

    if [ -z "$info" ] ; then
	echo "Interface ${i} missing... assuming already deleted!"
	continue
    fi

    echo "Deleting IPs on interface ${i}, with this information:"
    echo " $info"

    try_command_on_node $test_node "$CTDB ip -v -X | tail -n +2"
    awk -F'|' -v i="$i" \
	'$6 == i { print $2 }' <<<"$out" |
    while read ip ; do
	echo "  $ip"
	try_command_on_node $test_node "$CTDB delip $ip"
    done

    try_command_on_node $test_node "$CTDB ifaces -X"
    info=$(awk -F'|' -v iface="$i" '$2 == iface { print $0 }' <<<"$out")
    
    if [ -z "$info" ] ; then
	echo "GOOD: Interface ${i} has been garbage collected"
    else
	echo "BAD: Interface ${i} still exists"
	echo "$out"
	exit 1
    fi
done
