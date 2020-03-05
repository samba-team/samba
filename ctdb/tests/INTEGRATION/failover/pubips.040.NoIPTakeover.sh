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

# sets: num
count_ips_on_node ()
{
	local node="$1"

	ctdb_onnode "$node" ip
	# outfile is set by ctdb_onnode() above
	# shellcheck disable=SC2154,SC2126
	# * || true is needed to avoid command failure when there are no matches
	# * Using "wc -l | tr -d '[:space:]'" is our standard
	#   pattern... and "grep -c" requires handling of special case
	#   for no match
	num=$(grep -v 'Public' "$outfile" | \
		      grep " ${node}\$" | \
		      wc -l | \
		      tr -d '[:space:]')
	echo "Number of addresses on node ${node}: ${num}"
}

count_ips_on_node 1

echo "Turning on NoIPTakeover on all nodes"
try_command_on_node all "$CTDB setvar NoIPTakeover 1"
try_command_on_node 1 "$CTDB ipreallocate"

echo Disable node 1
try_command_on_node 1 "$CTDB disable"
try_command_on_node 1 "$CTDB ipreallocate"

count_ips_on_node 1
if [ "$num" != "0" ] ; then
	test_fail "BAD: node 1 still hosts IP addresses"
fi


echo "Enable node 1 again"
try_command_on_node 1 "$CTDB enable"
sleep_for 30
try_command_on_node 1 "$CTDB ipreallocate"
try_command_on_node 1 "$CTDB ipreallocate"

count_ips_on_node 1
if [ "$num" != "0" ] ; then
	test_fail "BAD: node 1 took over IP addresses"
fi


echo "OK. ip addresses were not taken over"
exit 0
