#!/bin/bash

# Verify that the recovery daemon correctly handles a rogue IP

# It should be released...

. "${TEST_SCRIPTS_DIR}/cluster.bash"

set -e

ctdb_test_init

select_test_node_and_ips

echo "Using $test_ip, which is onnode $test_node"

# This test depends on being able to assign a duplicate address on a
# 2nd node.  However, IPv6 guards against this and causes the test to
# fail.
case "$test_ip" in
*:*) ctdb_test_skip "This test is not supported for IPv6 addresses" ;;
esac

get_test_ip_mask_and_iface

echo "Finding another node that knows about $test_ip"
ctdb_get_all_pnns
other_node=""
for i in $all_pnns ; do
	if [ "$i" = "$test_node" ] ; then
		continue
	fi
	try_command_on_node $i "$CTDB ip"
	n=$(awk -v ip="$test_ip" '$1 == ip { print }' "$outfile")
	if [ -n "$n" ] ; then
		other_node="$i"
		break
	fi
done
if [ -z "$other_node" ] ; then
	die "Unable to find another node that knows about $test_ip"
fi

echo "Adding $test_ip on node $other_node"
try_command_on_node $other_node "ip addr add ${test_ip}/${mask} dev ${iface}"

rogue_ip_is_gone ()
{
	local pnn="$1"
	local test_ip="$2"
	try_command_on_node $pnn $CTDB_TEST_WRAPPER ip_maskbits_iface $test_ip
	[ -z "$out" ]
}

echo "Waiting until rogue IP is no longer assigned..."
wait_until 30 rogue_ip_is_gone $other_node $test_ip
