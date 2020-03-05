#!/usr/bin/env bash

# Verify that 'ctdb setvar NoIPTakeover 1' stops IP addresses being taken over

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

ctdb_get_all_pnns
# out is set above
# shellcheck disable=SC2154
num_nodes=$(echo "$out" | wc -l | tr -d '[:space:]')
echo "There are $num_nodes nodes..."

if [ "$num_nodes" -lt 2 ] ; then
    echo "Less than 2 nodes!"
    exit 1
fi

select_test_node_and_ips


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


# test_node is set by select_test_node_and_ips() above
# shellcheck disable=SC2154
count_ips_on_node "$test_node"

echo "Turning on NoIPTakeover on all nodes"
ctdb_onnode all "setvar NoIPTakeover 1"
ctdb_onnode "$test_node" ipreallocate

echo "Disable node ${test_node}"
ctdb_onnode "$test_node" disable

count_ips_on_node "$test_node"
if [ "$num" != "0" ] ; then
	test_fail "BAD: node 1 still hosts IP addresses"
fi


echo "Enable node 1 again"
ctdb_onnode "$test_node" enable

count_ips_on_node "$test_node"
if [ "$num" != "0" ] ; then
	test_fail "BAD: node 1 took over IP addresses"
fi


echo "OK: IP addresses were not taken over"
