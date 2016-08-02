#!/bin/bash

test_info()
{
    cat <<EOF
Verify that the recovery daemon correctly handles a rogue IP

It should be released...
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

echo "Using $test_ip, which is onnode $test_node"

get_test_ip_mask_and_iface

echo "Finding another node that knows about $test_ip"
ctdb_get_all_pnns
other_node=""
for i in $all_pnns ; do
	if [ "$i" = "$test_node" ] ; then
		continue
	fi
	try_command_on_node $i "$CTDB ip"
	n=$(awk -v ip="$test_ip" '$1 == ip { print }' <<<"$out")
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
